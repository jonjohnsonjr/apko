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

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"strconv"
	"time"

	apkimpl "github.com/chainguard-dev/go-apk/pkg/apk"
	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
	"github.com/hashicorp/go-multierror"
	"gitlab.alpinelinux.org/alpine/go/repository"
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
	executor        *exec.Executor
	s6              *s6.Context
	Assertions      []Assertion
	Options         options.Options
	fs              apkfs.FullFS
	apk             *apk.APK
}

func (bc *Context) Summarize() {
	bc.Logger().Printf("build context:")
	bc.Options.Summarize(bc.Logger())
	bc.ImageConfiguration.Summarize(bc.Logger())
}

func (bc *Context) InstalledPackages() ([]*apkimpl.InstalledPackage, error) {
	return bc.apk.GetInstalled()
}

func (bc *Context) GetBuildDateEpoch() (time.Time, error) {
	if _, ok := os.LookupEnv("SOURCE_DATE_EPOCH"); ok {
		return bc.Options.SourceDateEpoch, nil
	}
	pl, err := bc.InstalledPackages()
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

func (bc *Context) BuildImage() (fs.FS, error) {
	if err := bc.buildImage(); err != nil {
		logger := bc.Options.Logger()
		logger.Debugf("buildImage failed: %v", err)
		b, err2 := yaml.Marshal(bc.ImageConfiguration)
		if err2 != nil {
			logger.Debugf("failed to marshal image configuration: %v", err2)
		} else {
			logger.Debugf("image configuration:\n%s", string(b))
		}
		return nil, err
	}
	return bc.fs, nil
}

func (bc *Context) BuildPackageList() (toInstall []*repository.RepositoryPackage, conflicts []string, err error) {
	o := bc.Options

	o.Logger().Infof("doing pre-flight checks")
	if err := bc.ImageConfiguration.Validate(); err != nil {
		return toInstall, conflicts, fmt.Errorf("failed to validate configuration: %w", err)
	}

	o.Logger().Infof("building apk info in %s", o.WorkDir)

	if toInstall, conflicts, err = bc.apk.ResolvePackages(); err != nil {
		return toInstall, conflicts, fmt.Errorf("resolving apk packages: %w", err)
	}
	o.Logger().Infof("finished gathering apk info in %s", o.WorkDir)

	return toInstall, conflicts, err
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
func (bc *Context) BuildLayer() (string, error) {
	bc.Summarize()

	// build image filesystem
	if _, err := bc.BuildImage(); err != nil {
		return "", err
	}

	return bc.ImageLayoutToLayer()
}

// ImageLayoutToLayer given an already built-out
// image in an fs from BuildImage(), create
// an OCI image layer tgz.
func (bc *Context) ImageLayoutToLayer() (string, error) {
	// run any assertions defined
	if err := bc.runAssertions(); err != nil {
		return "", err
	}

	layerTarGZ, err := bc.BuildTarball()
	// build layer tarball
	if err != nil {
		return "", err
	}

	// generate SBOM
	if bc.Options.WantSBOM {
		if err := bc.GenerateSBOM(); err != nil {
			return "", fmt.Errorf("generating SBOMs: %w", err)
		}
	} else {
		bc.Logger().Debugf("Not generating SBOMs (WantSBOM = false)")
	}

	return layerTarGZ, nil
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
func New(fs apkfs.FullFS, opts ...Option) (*Context, error) {
	bc := Context{
		Options: options.Default,
		fs:      fs,
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

	var err error
	bc.apk, err = apk.NewWithOptions(bc.fs, bc.Options)
	if err != nil {
		return nil, err
	}

	return &bc, nil
}
