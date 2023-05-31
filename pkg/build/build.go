// Copyright 2022, 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package build

import (
	"compress/gzip"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/shlex"
	"github.com/hashicorp/go-multierror"
	"gopkg.in/yaml.v3"

	"chainguard.dev/apko/pkg/apk"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/exec"
	"chainguard.dev/apko/pkg/log"
	"chainguard.dev/apko/pkg/options"
	"chainguard.dev/apko/pkg/s6"
)

// Context contains all of the information necessary to build an
// OCI image. Includes the configurationfor the build,
// the path to the config file, the executor for root jails and
// architecture emulation, the s6 supervisor to add to the image,
// build options, and the `buildImplementation`, which handles the actual build.
type Context struct {
	// ImageConfiguration instructions to use for the build, normally from an apko.yaml file, but can be set directly.
	ImageConfiguration types.ImageConfiguration
	// ImageConfigFile path to the config file used, if any, to load the ImageConfiguration
	ImageConfigFile string

	Assertions []Assertion
	Options    options.Options

	apk      *apk.APK
	executor *exec.Executor
	s6       *s6.Context
	fs       apkfs.FullFS
}

func (bc *Context) Summarize() {
	bc.Logger().Printf("build context:")
	bc.Options.Summarize(bc.Logger())
	bc.ImageConfiguration.Summarize(bc.Logger())
}

func (bc *Context) GetBuildDateEpoch() (time.Time, error) {
	if _, ok := os.LookupEnv("SOURCE_DATE_EPOCH"); ok {
		return bc.Options.SourceDateEpoch, nil
	}
	pl, err := bc.apk.GetInstalled()
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to determine installed packages: %w", err)
	}
	bde := bc.Options.SourceDateEpoch
	for _, p := range pl {
		if p.BuildTime.After(bde) {
			bde = p.BuildTime
		}
	}
	return bde, nil
}

func (bc *Context) BuildFS() (fs.FS, error) {
	if err := bc.buildFS(); err != nil {
		bc.Logger().Debugf("buildFS failed: %v", err)
		b, err2 := yaml.Marshal(bc.ImageConfiguration)
		if err2 != nil {
			bc.Logger().Debugf("failed to marshal image configuration: %v", err2)
		} else {
			bc.Logger().Debugf("image configuration:\n%s", string(b))
		}
		return nil, err
	}
	return bc.fs, nil
}

func (bc *Context) Logger() log.Logger {
	return bc.Options.Logger()
}

// BuildLayer given the context set up, including
// build configuration and working directory,
// lays out all of the packages in the working directory,
// sets up the necessary user accounts and groups,
// and sets everything up in the directory. Then
// packages it all up into a standard OCI image layer
// tar.gz file.
func (bc *Context) BuildLayer() (string, v1.Layer, error) {
	bc.Summarize()

	// build image filesystem
	if _, err := bc.BuildFS(); err != nil {
		return "", nil, err
	}

	return bc.ImageLayoutToLayer()
}

func (bc *Context) BuildImage(layer v1.Layer) (v1.Image, error) {
	mediaType, err := layer.MediaType()
	if err != nil {
		return nil, fmt.Errorf("accessing layer MediaType: %w", err)
	}
	bc.Logger().Printf("building image from layer")

	ic := bc.ImageConfiguration

	digest, err := layer.Digest()
	if err != nil {
		return nil, fmt.Errorf("could not calculate layer digest: %w", err)
	}

	diffid, err := layer.DiffID()
	if err != nil {
		return nil, fmt.Errorf("could not calculate layer diff id: %w", err)
	}

	bc.Logger().Printf("layer digest: %v", digest)
	bc.Logger().Printf("layer diffID: %v", diffid)

	created := bc.Options.SourceDateEpoch

	adds := make([]mutate.Addendum, 0, 1)
	adds = append(adds, mutate.Addendum{
		Layer: layer,
		History: v1.History{
			Author:    "apko",
			Comment:   "This is an apko single-layer image",
			CreatedBy: "apko",
			Created:   v1.Time{Time: created},
		},
	})

	emptyImage := empty.Image
	if mediaType == ggcrtypes.OCILayer {
		// If building an OCI layer, then we should assume OCI manifest and config too
		emptyImage = mutate.MediaType(emptyImage, ggcrtypes.OCIManifestSchema1)
		emptyImage = mutate.ConfigMediaType(emptyImage, ggcrtypes.OCIConfigJSON)
	}
	img, err := mutate.Append(emptyImage, adds...)
	if err != nil {
		return nil, fmt.Errorf("unable to append layer to empty image: %w", err)
	}

	annotations := ic.Annotations
	if annotations == nil {
		annotations = map[string]string{}
	}
	if ic.VCSUrl != "" {
		if url, hash, ok := strings.Cut(ic.VCSUrl, "@"); ok {
			annotations["org.opencontainers.image.source"] = url
			annotations["org.opencontainers.image.revision"] = hash
		}
	}

	if mediaType != ggcrtypes.DockerLayer && len(annotations) > 0 {
		img = mutate.Annotations(img, annotations).(v1.Image)
	}

	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("unable to get config file: %w", err)
	}

	cfg = cfg.DeepCopy()
	cfg.Author = "github.com/chainguard-dev/apko"
	platform := bc.Options.Arch.ToOCIPlatform()
	cfg.Architecture = platform.Architecture
	cfg.Variant = platform.Variant
	cfg.Created = v1.Time{Time: created}
	cfg.Config.Labels = make(map[string]string)
	cfg.OS = "linux"

	// NOTE: Need to allow empty Entrypoints. The runtime will override to `/bin/sh -c` and handle quoting
	switch {
	case ic.Entrypoint.ShellFragment != "":
		cfg.Config.Entrypoint = []string{"/bin/sh", "-c", ic.Entrypoint.ShellFragment}
	case ic.Entrypoint.Command != "":
		splitcmd, err := shlex.Split(ic.Entrypoint.Command)
		if err != nil {
			return nil, fmt.Errorf("unable to parse entrypoint command: %w", err)
		}
		cfg.Config.Entrypoint = splitcmd
	}

	if ic.Cmd != "" {
		splitcmd, err := shlex.Split(ic.Cmd)
		if err != nil {
			return nil, fmt.Errorf("unable to parse cmd: %w", err)
		}
		cfg.Config.Cmd = splitcmd
	}

	if ic.WorkDir != "" {
		cfg.Config.WorkingDir = ic.WorkDir
	}

	if len(ic.Environment) > 0 {
		envs := []string{}

		for k, v := range ic.Environment {
			envs = append(envs, fmt.Sprintf("%s=%s", k, v))
		}
		sort.Strings(envs)

		cfg.Config.Env = envs
	} else {
		cfg.Config.Env = []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
		}
	}

	if ic.Accounts.RunAs != "" {
		cfg.Config.User = ic.Accounts.RunAs
	}

	if ic.StopSignal != "" {
		cfg.Config.StopSignal = ic.StopSignal
	}

	img, err = mutate.ConfigFile(img, cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to update config file: %w", err)
	}

	return img, nil
}

// ImageLayoutToLayer given an already built-out
// image in an fs from BuildFS(), create
// an OCI image layer tgz.
func (bc *Context) ImageLayoutToLayer() (string, v1.Layer, error) {
	// run any assertions defined
	if err := bc.runAssertions(); err != nil {
		return "", nil, err
	}

	layerTarGZ, diffid, digest, size, err := bc.BuildTarball()
	// build layer tarball
	if err != nil {
		return "", nil, err
	}

	// generate SBOM
	if bc.Options.WantSBOM {
		if err := bc.GenerateSBOM(); err != nil {
			return "", nil, fmt.Errorf("generating SBOMs: %w", err)
		}
	} else {
		bc.Logger().Debugf("Not generating SBOMs (WantSBOM = false)")
	}

	mt := ggcrtypes.OCILayer
	if bc.Options.UseDockerMediaTypes {
		mt = ggcrtypes.DockerLayer
	}

	l := &layer{
		filename: layerTarGZ,
		desc: &v1.Descriptor{
			Digest: v1.Hash{
				Algorithm: "sha256",
				Hex:       hex.EncodeToString(digest.Sum(make([]byte, 0, digest.Size()))),
			},
			Size:      size,
			MediaType: mt,
		},
		diffid: &v1.Hash{
			Algorithm: "sha256",
			Hex:       hex.EncodeToString(diffid.Sum(make([]byte, 0, diffid.Size()))),
		},
	}

	return layerTarGZ, l, nil
}
func (bc *Context) runAssertions() error {
	var eg multierror.Group

	for _, a := range bc.Assertions {
		a := a
		eg.Go(func() error { return a(bc) })
	}

	return eg.Wait().ErrorOrNil()
}

// New creates a build context.
// The SOURCE_DATE_EPOCH env variable is supported and will
// overwrite the provided timestamp if present.
func New(fsys apkfs.FullFS, opts ...Option) (*Context, error) {
	bc := Context{
		Options: options.Default,
		fs:      fsys,
	}

	for _, opt := range opts {
		if err := opt(&bc); err != nil {
			return nil, err
		}
	}

	// SOURCE_DATE_EPOCH will always overwrite the build flag
	if v, ok := os.LookupEnv("SOURCE_DATE_EPOCH"); ok {
		// The value MUST be an ASCII representation of an integer
		// with no fractional component, identical to the output
		// format of date +%s.
		sec, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			// If the value is malformed, the build process
			// SHOULD exit with a non-zero error code.
			return nil, fmt.Errorf("failed to parse SOURCE_DATE_EPOCH: %w", err)
		}

		bc.Options.SourceDateEpoch = time.Unix(sec, 0)
	}

	// if arch is missing default to the running program's arch
	zeroArch := types.Architecture("")
	if bc.Options.Arch == zeroArch {
		bc.Options.Arch = types.ParseArchitecture(runtime.GOARCH)
	}

	if bc.Options.WithVCS && bc.ImageConfiguration.VCSUrl == "" {
		bc.ImageConfiguration.ProbeVCSUrl(bc.ImageConfigFile, bc.Logger())
	}

	if err := bc.ImageConfiguration.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate configuration: %w", err)
	}

	apk, err := apk.NewWithOptions(fsys, bc.Options)
	if err != nil {
		return nil, err
	}
	if err := apk.Initialize(bc.ImageConfiguration); err != nil {
		return nil, err
	}
	bc.apk = apk

	return &bc, nil
}

// layer implements v1.Layer from go-containerregistry to avoid re-computing
// digests and diffids.
type layer struct {
	filename string
	diffid   *v1.Hash
	desc     *v1.Descriptor
}

func (l *layer) DiffID() (v1.Hash, error) {
	return *l.diffid, nil
}

func (l *layer) Digest() (v1.Hash, error) {
	return l.desc.Digest, nil
}

func (l *layer) Compressed() (io.ReadCloser, error) {
	return os.Open(l.filename)
}

func (l *layer) Uncompressed() (io.ReadCloser, error) {
	rc, err := l.Compressed()
	if err != nil {
		return nil, err
	}

	// In practice, this won't be called, but this should work anyway.
	zr, err := gzip.NewReader(rc)
	if err != nil {
		return nil, err
	}
	return zr, nil
}

func (l *layer) Size() (int64, error) {
	return l.desc.Size, nil
}

func (l *layer) MediaType() (ggcrtypes.MediaType, error) {
	return l.desc.MediaType, nil
}
