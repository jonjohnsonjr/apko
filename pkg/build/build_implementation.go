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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/chainguard-dev/go-apk/pkg/tarball"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	coci "github.com/sigstore/cosign/v2/pkg/oci"
	"sigs.k8s.io/release-utils/hash"

	chainguardAPK "chainguard.dev/apko/pkg/apk"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/exec"
	"chainguard.dev/apko/pkg/s6"
	"chainguard.dev/apko/pkg/sbom"
	"chainguard.dev/apko/pkg/sbom/generator"
	soptions "chainguard.dev/apko/pkg/sbom/options"
)

// Refresh initializes the build process by calling the underlying implementation's
// Refresh(), which includes getting the chroot/proot jailed process executor (and
// possibly architecture emulator), sets those on the Context, and returns.
func (bc *Context) Refresh() error {
	fsys, o := bc.fs, bc.Options
	o.TarballPath = ""
	hostArch := types.ParseArchitecture(runtime.GOARCH)

	if !o.Arch.Compatible(hostArch) {
		o.Logger().Warnf("%q requires QEMU binfmt emulation to be configured (not compatible with %q)", o.Arch, hostArch)
	}

	executor, err := exec.New(o.WorkDir, o.Logger())
	if err != nil {
		return err
	}
	bc.executor = executor
	bc.s6 = s6.New(fsys, o.Logger())

	return nil
}

// BuildTarball calls the underlying implementation's BuildTarball
// which takes the fully populated working directory and saves it to
// an OCI image layer tar.gz file.
func (bc *Context) BuildTarball() (string, error) {
	fsys, o := bc.fs, bc.Options

	var outfile *os.File
	var err error

	if o.TarballPath != "" {
		outfile, err = os.Create(o.TarballPath)
	} else {
		outfile, err = os.Create(filepath.Join(o.TempDir(), o.TarballFileName()))
	}
	if err != nil {
		return "", fmt.Errorf("opening the build context tarball path failed: %w", err)
	}
	o.TarballPath = outfile.Name()
	defer outfile.Close()

	// we use a general override of 0,0 for all files, but the specific overrides, that come from the installed package DB, come later
	tw, err := tarball.NewContext(
		tarball.WithSourceDateEpoch(o.SourceDateEpoch),
	)
	if err != nil {
		return "", fmt.Errorf("failed to construct tarball build context: %w", err)
	}

	if err := tw.WriteArchive(outfile, fsys); err != nil {
		return "", fmt.Errorf("failed to generate tarball for image: %w", err)
	}

	o.Logger().Infof("built image layer tarball as %s", outfile.Name())
	return outfile.Name(), nil
}

func (bc *Context) GenerateImageSBOM(arch types.Architecture, img coci.SignedImage) ([]string, error) {
	if len(bc.Options.SBOMFormats) == 0 {
		bc.Options.Logger().Warnf("skipping SBOM generation")
		return nil, nil
	}

	layerDigest, err := sbom.ReadLayerTarball(bc.Options.TarballPath)
	if err != nil {
		return nil, fmt.Errorf("reading layer tar: %w", err)
	}

	osd, err := sbom.ReadReleaseData(bc.fs)
	if err != nil {
		return nil, fmt.Errorf("getting os-release: %w", err)
	}

	pkgs, err := sbom.ReadPackageIndex(bc.fs)
	if err != nil {
		return nil, fmt.Errorf("getting installed packages from sbom: %w", err)
	}

	// Get the image digest
	h, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("getting %s image digest: %w", bc.Options.Arch, err)
	}

	sopt := bc.sbopt()
	sopt.ImageInfo.LayerDigest = layerDigest.String()
	sopt.ImageInfo.ImageDigest = h.String()
	sopt.ImageInfo.Arch = arch
	sopt.OS.Name = osd.Name
	sopt.OS.ID = osd.ID
	sopt.OS.Version = osd.Version
	sopt.Packages = pkgs

	files := []string{}
	for _, format := range bc.Options.SBOMFormats {
		gen, ok := generator.Generators[format]
		if !ok {
			return nil, fmt.Errorf("no sbom generator for format %s", format)
		}
		path := filepath.Join(sopt.OutputDir, sopt.FileName(gen.Ext()))
		if err := gen.Generate(bc.fs, *sopt, path); err != nil {
			return nil, fmt.Errorf("generating %s sbom: %w", format, err)
		}
		files = append(files, path)
	}

	return files, nil
}

func (bc *Context) GenerateLayerSBOM(path string) ([]string, error) {
	if len(bc.Options.SBOMFormats) == 0 {
		bc.Options.Logger().Warnf("skipping index SBOM generation")
		return nil, nil
	}

	layerDigest, err := sbom.ReadLayerTarball(path)
	if err != nil {
		return nil, fmt.Errorf("reading layer tar: %w", err)
	}

	osd, err := sbom.ReadReleaseData(bc.fs)
	if err != nil {
		return nil, fmt.Errorf("getting os-release: %w", err)
	}

	pkgs, err := sbom.ReadPackageIndex(bc.fs)
	if err != nil {
		return nil, fmt.Errorf("getting installed packages from sbom: %w", err)
	}

	sopt := bc.sbopt()
	sopt.ImageInfo.LayerDigest = layerDigest.String()
	sopt.OS.Name = osd.Name
	sopt.OS.ID = osd.ID
	sopt.OS.Version = osd.Version
	sopt.Packages = pkgs

	files := []string{}
	for _, format := range bc.Options.SBOMFormats {
		gen, ok := generator.Generators[format]
		if !ok {
			return nil, fmt.Errorf("no sbom generator for format %s", format)
		}
		path := filepath.Join(sopt.OutputDir, sopt.FileName(gen.Ext()))
		if err := gen.Generate(bc.fs, *sopt, path); err != nil {
			return nil, fmt.Errorf("generating %s sbom: %w", format, err)
		}
		files = append(files, path)
	}

	return files, nil
}

func (bc *Context) buildImage() error {
	fsys, o, ic := bc.fs, bc.Options, bc.ImageConfiguration

	o.Logger().Infof("doing pre-flight checks")
	if err := ic.Validate(); err != nil {
		return fmt.Errorf("failed to validate configuration: %w", err)
	}

	o.Logger().Infof("building image fileystem in %s", o.WorkDir)

	if err := bc.apk.Initialize(&ic); err != nil {
		return fmt.Errorf("initializing apk: %w", err)
	}

	if err := bc.apk.Install(); err != nil {
		return fmt.Errorf("installing apk packages: %w", err)
	}

	at, err := chainguardAPK.AdditionalTags(fsys, o)
	if err != nil {
		return fmt.Errorf("adding additional tags: %w", err)
	}
	if at != nil {
		o.Tags = append(o.Tags, at...)
	}

	if err := bc.MutateAccounts(); err != nil {
		return fmt.Errorf("failed to mutate accounts: %w", err)
	}

	if err = bc.MutatePaths(); err != nil {
		return fmt.Errorf("failed to mutate paths: %w", err)
	}

	if err := bc.GenerateOSRelease(); err != nil {
		if errors.Is(err, ErrOSReleaseAlreadyPresent) {
			o.Logger().Warnf("did not generate /etc/os-release: %v", err)
		} else {
			return fmt.Errorf("failed to generate /etc/os-release: %w", err)
		}
	}

	if err := bc.WriteSupervisionTree(); err != nil {
		return err
	}

	// add busybox symlinks
	if err := bc.InstallBusyboxLinks(); err != nil {
		return err
	}

	// add ldconfig links
	if err := bc.InstallLdconfigLinks(); err != nil {
		return err
	}

	// add necessary character devices
	if err := bc.InstallCharDevices(); err != nil {
		return err
	}

	o.Logger().Infof("finished building filesystem in %s", o.WorkDir)

	return nil

}

func (bc *Context) sbopt() *soptions.Options {
	o, ic := bc.Options, bc.ImageConfiguration

	sopt := sbom.DefaultOptions()
	// Parse the image reference
	if len(o.Tags) > 0 {
		tag, err := name.NewTag(o.Tags[0])
		if err == nil {
			sopt.ImageInfo.Tag = tag.TagStr()
			sopt.ImageInfo.Name = tag.String()
		} else {
			o.Logger().Errorf("%s parsing tag %s, ignoring", o.Tags[0], err)
		}
	}

	sopt.ImageInfo.SourceDateEpoch = o.SourceDateEpoch
	sopt.ImageInfo.VCSUrl = ic.VCSUrl

	if o.UseDockerMediaTypes {
		sopt.ImageInfo.ImageMediaType = ggcrtypes.DockerManifestSchema2
	} else {
		sopt.ImageInfo.ImageMediaType = ggcrtypes.OCIManifestSchema1
	}

	sopt.OutputDir = o.TempDir()
	if o.SBOMPath != "" {
		sopt.OutputDir = o.SBOMPath
	}

	return sopt
}

func (bc *Context) GenerateIndexSBOM(indexDigest name.Digest, imgs map[types.Architecture]coci.SignedImage) ([]string, error) {
	o := bc.Options
	if len(o.SBOMFormats) == 0 {
		o.Logger().Warnf("skipping index SBOM generation")
		return nil, nil
	}

	sopt := bc.sbopt()
	o.Logger().Infof("Generating index SBOM")

	// Add the image digest
	h, err := v1.NewHash(indexDigest.DigestStr())
	if err != nil {
		return nil, errors.New("getting index hash")
	}
	sopt.ImageInfo.IndexDigest = h

	sopt.ImageInfo.IndexMediaType = ggcrtypes.OCIImageIndex
	if o.UseDockerMediaTypes {
		sopt.ImageInfo.IndexMediaType = ggcrtypes.DockerManifestList
	}

	sboms := []string{}
	for _, format := range o.SBOMFormats {
		gen, ok := generator.Generators[format]
		if !ok {
			return nil, fmt.Errorf("no sbom generator for format %s", format)
		}

		// Load the images data into the SBOM generator options
		for arch, i := range imgs {
			// TODO(jonjohnsonjr): This is wrong, actually. Need to think about arch.
			sbomHash, err := hash.SHA256ForFile(filepath.Join(sopt.OutputDir, sopt.FileName(gen.Ext())))
			if err != nil {
				return nil, fmt.Errorf("checksumming %s SBOM: %w", arch, err)
			}

			d, err := i.Digest()
			if err != nil {
				return nil, fmt.Errorf("getting arch image digest: %w", err)
			}

			sopt.ImageInfo.Images = append(
				sopt.ImageInfo.Images,
				soptions.ArchImageInfo{
					Digest:     d,
					Arch:       arch,
					SBOMDigest: sbomHash,
				})
		}

		// TODO(jonjohnsonjr): make image arch "index"?
		// path := filepath.Join(opts.OutputDir, "sbom-index."+gen.Ext())
		sopt.ImageInfo.Arch = "index"
		path := filepath.Join(sopt.OutputDir, sopt.FileName(gen.Ext()))

		if err := gen.GenerateIndex(bc.fs, *sopt, path); err != nil {
			return nil, fmt.Errorf("generating %s index sbom: %w", format, err)
		}
		sboms = append(sboms, path)
	}

	return sboms, nil
}
