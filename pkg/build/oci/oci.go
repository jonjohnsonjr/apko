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

package oci

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/avast/retry-go"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ocimutate "github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/signed"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/cosign/v2/pkg/oci/walk"
	ctypes "github.com/sigstore/cosign/v2/pkg/types"
	"golang.org/x/sync/errgroup"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/log"
	"github.com/chainguard-dev/go-apk/pkg/tarball"
)

const (
	LocalDomain = "apko.local"
	LocalRepo   = "cache"
)

func Copy(ctx context.Context, src, dst string, remoteOpts ...remote.Option) error {
	log.DefaultLogger().Infof("Copying %s to %s", src, dst)
	srcRef, err := name.ParseReference(src)
	if err != nil {
		return err
	}
	dstRef, err := name.ParseReference(dst)
	if err != nil {
		return err
	}
	desc, err := remote.Get(srcRef, remoteOpts...)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", src, err)
	}
	pusher, err := remote.NewPusher(remoteOpts...)
	if err != nil {
		return err
	}
	if err := pusher.Push(ctx, dstRef, desc); err != nil {
		return fmt.Errorf("tagging %s with tag %s: %w", src, dst, err)
	}

	return nil
}

// PostAttachSBOM attaches the sboms to an already published image
func PostAttachSBOM(ctx context.Context, si oci.SignedEntity, sbomPath string, sbomFormats []string, arch types.Architecture, logger log.Logger, tags []string, remoteOpts ...remote.Option) (oci.SignedEntity, error) {
	si, err := AttachSBOM(si, sbomPath, sbomFormats, arch, logger)
	if err != nil {
		return nil, err
	}
	var g errgroup.Group
	seen := map[string]struct{}{}
	for _, tag := range tags {
		ref, err := name.ParseReference(tag)
		if err != nil {
			return nil, fmt.Errorf("parsing reference: %w", err)
		}
		repo := ref.Context()
		if _, ok := seen[repo.String()]; ok {
			continue
		}

		seen[repo.String()] = struct{}{}

		// Write any attached SBOMs/signatures.
		wp := writePeripherals(repo, logger, remoteOpts...)
		g.Go(func() error {
			return wp(ctx, si)
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return si, nil
}

func AttachSBOM(si oci.SignedEntity, sbomPath string, sbomFormats []string, arch types.Architecture, logger log.Logger) (oci.SignedEntity, error) {
	// Attach the SBOM, e.g.
	// TODO(kaniini): Allow all SBOM types to be uploaded.
	if len(sbomFormats) == 0 {
		log.DefaultLogger().Debugf("Not building sboms, no formats requested")
		return si, nil
	}

	var mt ggcrtypes.MediaType
	var path string
	archName := arch.ToAPK()
	if archName == "" {
		archName = "index"
	}
	switch sbomFormats[0] {
	case "spdx":
		mt = ctypes.SPDXJSONMediaType
		path = filepath.Join(sbomPath, fmt.Sprintf("sbom-%s.spdx.json", archName))
	case "cyclonedx":
		mt = ctypes.CycloneDXJSONMediaType
		path = filepath.Join(sbomPath, fmt.Sprintf("sbom-%s.cdx", archName))
	case "idb":
		mt = "application/vnd.apko.installed-db"
		path = filepath.Join(sbomPath, fmt.Sprintf("sbom-%s.idb", archName))
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %s", sbomFormats[0])
	}
	if len(sbomFormats) > 1 {
		// When we have multiple formats, warn that we're picking the first.
		logger.Warnf("multiple SBOM formats requested, uploading SBOM with media type: %s", mt)
	}

	sbom, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading sbom: %w", err)
	}

	f, err := static.NewFile(sbom, static.WithLayerMediaType(mt))
	if err != nil {
		return nil, err
	}
	var aterr error
	if i, ok := si.(oci.SignedImage); ok {
		si, aterr = ocimutate.AttachFileToImage(i, "sbom", f)
	} else if ii, ok := si.(oci.SignedImageIndex); ok {
		si, aterr = ocimutate.AttachFileToImageIndex(ii, "sbom", f)
	} else {
		return nil, errors.New("unable to cast signed signedentity as image or index")
	}
	if aterr != nil {
		return nil, fmt.Errorf("attaching file to image: %w", aterr)
	}

	return si, nil
}

func LoadImage(ctx context.Context, image oci.SignedImage, imageRef string, logger log.Logger) (name.Digest, error) {
	hash, err := image.Digest()
	if err != nil {
		return name.Digest{}, err
	}
	localSrcTagStr := fmt.Sprintf("%s/%s:%s", LocalDomain, LocalRepo, hash.Hex)
	localSrcTag, err := name.NewTag(localSrcTagStr)
	if err != nil {
		return name.Digest{}, err
	}
	logger.Infof("saving OCI image locally: %s", localSrcTag.Name())
	resp, err := daemon.Write(localSrcTag, image)
	if err != nil {
		logger.Errorf("docker daemon error: %s", strings.ReplaceAll(resp, "\n", "\\n"))
		return name.Digest{}, fmt.Errorf("failed to save OCI image locally: %w", err)
	}
	logger.Debugf("docker daemon response: %s", strings.ReplaceAll(resp, "\n", "\\n"))
	localDstTag, err := name.NewTag(imageRef)
	if err != nil {
		return name.Digest{}, err
	}
	if strings.HasPrefix(localSrcTag.Name(), fmt.Sprintf("%s/", LocalDomain)) {
		logger.Warnf("skipping local domain tagging %s as %s", localSrcTag.Name(), localDstTag.Name())
	} else {
		logger.Printf("tagging local image %s as %s", localSrcTag.Name(), localDstTag.Name())
		if err := daemon.Tag(localSrcTag, localDstTag); err != nil {
			return name.Digest{}, err
		}
	}
	return name.NewDigest(fmt.Sprintf("%s@%s", localSrcTag.Name(), hash))
}

func PublishImageDigest(ctx context.Context, si oci.SignedImage, ref name.Digest, logger log.Logger, remoteOpts ...remote.Option) (name.Digest, error) {
	logger.Printf("publishing image without tag (digest only)")

	var g errgroup.Group

	// Write any attached SBOMs/signatures.
	wp := writePeripherals(ref.Context(), logger, remoteOpts...)
	g.Go(func() error {
		return wp(ctx, si)
	})

	g.Go(func() error {
		return retry.Do(func() error {
			return remote.Write(ref, si, remoteOpts...)
		})
	})

	if err := g.Wait(); err != nil {
		return name.Digest{}, fmt.Errorf("failed to publish: %w", err)
	}
	return ref, nil
}

func PublishImageTags(ctx context.Context, si oci.SignedImage, logger log.Logger, tags []string, remoteOpts ...remote.Option) (name.Digest, error) {
	h, err := si.Digest()
	if err != nil {
		return name.Digest{}, fmt.Errorf("failed to compute digest: %w", err)
	}

	var g errgroup.Group

	digest := name.Digest{}
	for i, tag := range tags {
		logger.Printf("publishing image tag %v", tag)
		ref, err := name.ParseReference(tag)
		if err != nil {
			return name.Digest{}, fmt.Errorf("unable to parse reference: %w", err)
		}

		if i == 0 {
			digest = ref.Context().Digest(h.String())
		}

		// Write any attached SBOMs/signatures.
		wp := writePeripherals(ref.Context(), logger, remoteOpts...)
		g.Go(func() error {
			return wp(ctx, si)
		})

		g.Go(func() error {
			return retry.Do(func() error {
				return remote.Write(ref, si, remoteOpts...)
			})
		})
	}

	if err := g.Wait(); err != nil {
		return name.Digest{}, fmt.Errorf("failed to publish: %w", err)
	}

	return digest, nil
}

func PublishImage(ctx context.Context, si oci.SignedImage, logger log.Logger, local bool, pushTags bool, tags []string, remoteOpts ...remote.Option) (name.Digest, error) {
	imageRef := tags[0]
	if local {
		return LoadImage(ctx, si, imageRef, logger)
	}

	if !pushTags {
		h, err := si.Digest()
		if err != nil {
			return name.Digest{}, err
		}

		tag, err := name.ParseReference(imageRef)
		if err != nil {
			return name.Digest{}, err
		}

		dig := tag.Context().Digest(h.String())
		return PublishImageDigest(ctx, si, dig, logger, remoteOpts...)
	}

	return PublishImageTags(ctx, si, logger, tags, remoteOpts...)
}

// TODO: This should write the image, too.
func LoadIndex(ctx context.Context, idx oci.SignedImageIndex, logger log.Logger, tags []string) (name.Digest, error) {
	im, err := idx.IndexManifest()
	if err != nil {
		return name.Digest{}, err
	}
	goos, goarch := os.Getenv("GOOS"), os.Getenv("GOARCH")
	if goos == "" {
		goos = "linux"
	}
	if goarch == "" {
		goarch = "amd64"
	}
	// Default to just using the first one in the list if we cannot match
	useManifest := im.Manifests[0]
	for _, manifest := range im.Manifests {
		if manifest.Platform == nil {
			continue
		}
		if manifest.Platform.OS != goos {
			continue
		}
		if manifest.Platform.Architecture != goarch {
			continue
		}
		useManifest = manifest
	}
	localSrcTagStr := fmt.Sprintf("%s/%s:%s", LocalDomain, LocalRepo, useManifest.Digest.Hex)
	logger.Printf("using best guess single-arch image for local tags: %s (%s/%s)", localSrcTagStr, goos, goarch)
	localSrcTag, err := name.NewTag(localSrcTagStr)
	if err != nil {
		return name.Digest{}, err
	}
	for _, tag := range tags {
		localDstTag, err := name.NewTag(tag)
		if err != nil {
			return name.Digest{}, err
		}
		if strings.HasPrefix(localSrcTag.Name(), fmt.Sprintf("%s/", LocalDomain)) {
			logger.Warnf("skipping local domain tagging %s as %s", localSrcTag.Name(), localDstTag.Name())
		} else {
			logger.Printf("tagging local image %s as %s", localSrcTag.Name(), localDstTag.Name())
			if err := daemon.Tag(localSrcTag, localDstTag); err != nil {
				return name.Digest{}, err
			}
		}
	}
	digest, err := name.NewDigest(fmt.Sprintf("%s@%s", localSrcTag.Name(), useManifest.Digest.String()))
	if err != nil {
		return name.Digest{}, err
	}
	return digest, nil
}

func PublishIndexDigest(ctx context.Context, idx oci.SignedImageIndex, ref name.Digest, logger log.Logger, remoteOpts ...remote.Option) (name.Digest, error) {
	logger.Printf("publishing index without tag (digest only)")

	var g errgroup.Group

	// Write any attached SBOMs/signatures (recursively)
	wp := writePeripherals(ref.Context(), logger, remoteOpts...)
	if err := walk.SignedEntity(ctx, idx, func(ctx context.Context, se oci.SignedEntity) error {
		g.Go(func() error {
			return wp(ctx, se)
		})
		return nil
	}); err != nil {
		return name.Digest{}, err
	}

	g.Go(func() error {
		return retry.Do(func() error {
			return remote.WriteIndex(ref, idx, remoteOpts...)
		})
	})
	if err := g.Wait(); err != nil {
		return name.Digest{}, fmt.Errorf("failed to publish: %w", err)
	}

	return ref, nil
}

func PublishIndexTags(ctx context.Context, idx oci.SignedImageIndex, logger log.Logger, tags []string, remoteOpts ...remote.Option) error {
	var g errgroup.Group

	for _, tag := range tags {
		ref, err := name.ParseReference(tag)
		if err != nil {
			return fmt.Errorf("unable to parse reference: %w", err)
		}

		logger.Printf("publishing index tag %v", tag)

		// Write any attached SBOMs/signatures (recursively)
		wp := writePeripherals(ref.Context(), logger, remoteOpts...)
		if err := walk.SignedEntity(ctx, idx, func(ctx context.Context, se oci.SignedEntity) error {
			g.Go(func() error {
				return wp(ctx, se)
			})
			return nil
		}); err != nil {
			return err
		}

		g.Go(func() error {
			return retry.Do(func() error {
				return remote.WriteIndex(ref, idx, remoteOpts...)
			})
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("failed to publish: %w", err)
	}

	return nil
}

func PublishIndex(ctx context.Context, idx oci.SignedImageIndex, logger log.Logger, local bool, shouldPushTags bool, tags []string, remoteOpts ...remote.Option) (name.Digest, error) {
	// TODO(jason): Also set annotations on the index. ggcr's
	// pkg/v1/mutate.Annotations will drop the interface methods from
	// oci.SignedImageIndex, so we may need to reimplement
	// mutate.Annotations in ocimutate to keep it for now.

	// If attempting to save locally, pick the native architecture
	// and use that cached image for local tags
	// Ported from https://github.com/ko-build/ko/blob/main/pkg/publish/daemon.go#L92-L168
	if local {
		return LoadIndex(ctx, idx, logger, tags)
	}

	h, err := idx.Digest()
	if err != nil {
		return name.Digest{}, err
	}

	ref, err := name.ParseReference(tags[0])
	if err != nil {
		return name.Digest{}, err
	}

	dig := ref.Context().Digest(h.String())

	if !shouldPushTags {
		return PublishIndexDigest(ctx, idx, dig, logger, remoteOpts...)
	}

	if err := PublishIndexTags(ctx, idx, logger, tags, remoteOpts...); err != nil {
		return name.Digest{}, err
	}

	return dig, nil
}

func BuildIndex(imgs map[types.Architecture]oci.SignedImage, docker bool) (oci.SignedImageIndex, error) {
	mediaType := ggcrtypes.OCIImageIndex
	if docker {
		mediaType = ggcrtypes.DockerManifestList
	}
	idx := signed.ImageIndex(mutate.IndexMediaType(empty.Index, mediaType))
	archs := make([]types.Architecture, 0, len(imgs))
	for arch := range imgs {
		archs = append(archs, arch)
	}
	sort.Slice(archs, func(i, j int) bool {
		return archs[i].String() < archs[j].String()
	})
	for _, arch := range archs {
		img := imgs[arch]
		mt, err := img.MediaType()
		if err != nil {
			return nil, fmt.Errorf("failed to get mediatype: %w", err)
		}

		h, err := img.Digest()
		if err != nil {
			return nil, fmt.Errorf("failed to compute digest: %w", err)
		}

		size, err := img.Size()
		if err != nil {
			return nil, fmt.Errorf("failed to compute size: %w", err)
		}

		idx = ocimutate.AppendManifests(idx, ocimutate.IndexAddendum{
			Add: img,
			Descriptor: v1.Descriptor{
				MediaType: mt,
				Digest:    h,
				Size:      size,
				Platform:  arch.ToOCIPlatform(),
			},
		})
	}

	return idx, nil
}

func WriteIndex(outfile string, idx v1.ImageIndex, logger log.Logger) (name.Digest, error) {
	dir, err := os.MkdirTemp("", "apko-layout")
	if err != nil {
		return name.Digest{}, err
	}
	if _, err := layout.Write(dir, idx); err != nil {
		return name.Digest{}, err
	}

	f, err := os.OpenFile(outfile, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return name.Digest{}, fmt.Errorf("failed to open outfile %s: %w", outfile, err)
	}
	defer f.Close()

	fs := os.DirFS(dir)
	tw, err := tarball.NewContext()
	if err := tw.WriteTargz(context.TODO(), f, fs); err != nil {
		return name.Digest{}, err
	}

	h, err := idx.Digest()
	if err != nil {
		return name.Digest{}, err
	}
	digest, err := name.NewDigest(fmt.Sprintf("%s@%s", "image", h.String()))
	if err != nil {
		return name.Digest{}, err
	}
	return digest, nil
}

func writePeripherals(repo name.Repository, logger log.Logger, opt ...remote.Option) walk.Fn {
	ociOpts := []ociremote.Option{ociremote.WithRemoteOptions(opt...)}

	// Respect COSIGN_REPOSITORY
	targetRepoOverride, err := ociremote.GetEnvTargetRepository()
	if err != nil {
		return func(ctx context.Context, se oci.SignedEntity) error { return err }
	}
	if (targetRepoOverride != name.Repository{}) {
		ociOpts = append(ociOpts, ociremote.WithTargetRepository(targetRepoOverride))
	}

	return func(ctx context.Context, se oci.SignedEntity) error {
		h, err := se.(interface{ Digest() (v1.Hash, error) }).Digest()
		if err != nil {
			return err
		}

		// TODO(mattmoor): We should have a WriteSBOM helper upstream.
		digest := repo.Digest(h.String()) // Don't *get* the tag, we know the digest
		ref, err := ociremote.SBOMTag(digest, ociOpts...)
		if err != nil {
			return err
		}

		f, err := se.Attachment("sbom")
		if err != nil {
			// Some levels (e.g. the index) may not have an SBOM,
			// just like some levels may not have signatures/attestations.
			return nil
		}

		if err := retry.Do(func() error {
			return remote.Write(ref, f, opt...)
		}); err != nil {
			return fmt.Errorf("writing sbom: %w", err)
		}

		// TODO(mattmoor): Don't enable this until we start signing or it
		// will publish empty signatures!
		// if err := ociremote.WriteSignatures(tag.Context(), se, ociOpts...); err != nil {
		// 	return err
		// }

		// TODO(mattmoor): Are there any attestations we want to write?
		// if err := ociremote.WriteAttestations(tag.Context(), se, ociOpts...); err != nil {
		// 	return err
		// }
		logger.Printf("Published SBOM %v", ref)

		return nil
	}
}
