package build

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"

	"chainguard.dev/apko/pkg/apk"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
	goapk "github.com/chainguard-dev/go-apk/pkg/apk"
	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
)

type countWriter struct {
	n int64
}

func (w *countWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}

func BuildTarball2(ctx context.Context, fsys apkfs.FullFS, o *options.Options, ic *types.ImageConfiguration) (string, hash.Hash, hash.Hash, int64, error) {
	o.Logger().Infof("doing pre-flight checks")
	if err := ic.Validate(); err != nil {
		return "", nil, nil, 0, fmt.Errorf("failed to validate configuration: %w", err)
	}

	o.Logger().Infof("building image fileystem in %s", o.WorkDir)

	var w *os.File
	var err error

	if o.TarballPath != "" {
		w, err = os.Create(o.TarballPath)
	} else {
		w, err = os.Create(filepath.Join(o.TempDir(), o.TarballFileName()))
	}
	if err != nil {
		return "", nil, nil, 0, fmt.Errorf("opening the build context tarball path failed: %w", err)
	}

	o.TarballPath = w.Name()
	defer w.Close()

	o.Logger().Infof("building tarball in %s", w.Name())

	cw := &countWriter{}
	digest := sha256.New()
	zmw := io.MultiWriter(w, digest, cw)

	zw := gzip.NewWriter(zmw)

	diffid := sha256.New()
	mw := io.MultiWriter(zw, diffid)

	tw := tar.NewWriter(mw)

	if err := func() error {
		a, err := apk.NewWithOptions(fsys, *o)
		if err != nil {
			return err
		}

		// TODO: We should not need to do this, but SBOMs assume it.
		if err := a.Initialize(ctx, ic); err != nil {
			return fmt.Errorf("failed to initialize apk: %w", err)
		}

		// TODO: Or this.
		osr := filepath.Join("etc", "os-release")
		b := []byte(CreateOSRelease(ic))
		if err := fsys.WriteFile(osr, b, 0644); err != nil {
			return fmt.Errorf("creating etc/os-release: %w", err)
		}

		// TODO: We probably want to append these last to overwrite existing stuff.
		// Alternatively, we can keep a list of files to omit and pass that to SplitAPK.
		arch := o.Arch.ToAPK()
		if err := goapk.AppendInitFiles(tw, arch); err != nil {
			return fmt.Errorf("failed to initialize apk database: %w", err)
		}

		alpineVersions := apk.ParseOptionsFromRepositories(ic.Contents.Repositories)
		if len(alpineVersions) != 0 {
			if err := goapk.AppendAlpineKeys(ctx, tw, arch, alpineVersions); err != nil {
				return fmt.Errorf("failed to initialize apk keyring: %w", err)
			}
		}

		if err := goapk.AppendKeyring(ctx, tw, ic.Contents.Keyring, a.Options.ExtraKeyFiles); err != nil {
			return fmt.Errorf("failed to initialize apk keyring: %w", err)
		}

		repos := make([]string, 0, len(ic.Contents.Repositories)+len(a.Options.ExtraRepos))
		repos = append(repos, ic.Contents.Repositories...)
		repos = append(repos, a.Options.ExtraRepos...)
		if err := goapk.AppendRepositories(ctx, tw, repos); err != nil {
			return fmt.Errorf("failed to initialize apk repositories: %w", err)
		}

		packages := make([]string, 0, len(ic.Contents.Packages)+len(a.Options.ExtraPackages))
		packages = append(packages, ic.Contents.Packages...)
		packages = append(packages, a.Options.ExtraPackages...)
		if err := goapk.AppendWorld(ctx, tw, packages); err != nil {
			return fmt.Errorf("failed to initialize apk world: %w", err)
		}

		// TODO: Record paths in ic to track in case we need to chmod existing file (by re-appending).
		//
		// AppendAccounts:
		// - etc/group
		// - etc/passwd
		// - homedirs???
		//
		// AppendPaths:
		//  - mut.Path if mut.Type = "permissions"

		allpkgs, conflicts, err := a.ResolvePackages(ctx)
		if err != nil {
			return fmt.Errorf("error getting package dependencies: %w", err)
		}
		if len(conflicts) != 0 {
			o.Logger().Printf("TODO(conflicts???): %v", conflicts)
		}

		// TODO(jonjohnsonjr): Track what we need.
		if err := AppendAccounts(tw, ic); err != nil {
			return fmt.Errorf("failed to mutate accounts: %w", err)
		}

		// TODO(jonjohnsonjr): Track what we need.
		if err := AppendPaths(tw, ic); err != nil {
			return fmt.Errorf("failed to mutate paths: %w", err)
		}

		if err := AppendOSRelease(tw, ic); err != nil {
			return fmt.Errorf("failed to generate /etc/os-release: %w", err)
		}

		if err := AppendSupervisionTree(tw, ic); err != nil {
			return fmt.Errorf("failed to write supervision tree: %w", err)
		}

		// TODO(jonjohnsonjr): Fix this later.
		//
		// add busybox symlinks
		// if err := di.InstallBusyboxLinks(fsys, o); err != nil {
		// 	return err
		// }

		// TODO(jonjohnsonjr): This appears to be a no-op.
		//
		// add ldconfig links
		// if err := di.InstallLdconfigLinks(fsys); err != nil {
		// 	return err
		// }

		// TODO: fan out and sync.Once this stuff
		splits := make([]*goapk.SplitApk, 0, len(allpkgs))
		for _, pkg := range allpkgs {
			o.Logger().Printf("splitting %s", pkg.Filename())

			// TODO(jonjohnsonjr): Do we need to check if pkgs are already installed?
			split, err := a.SplitApk(ctx, pkg)
			if err != nil {
				return err
			}

			splits = append(splits, split)
		}

		installedFile, err := fsys.OpenFile("lib/apk/db/installed", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("could not open installed file for write: %w", err)
		}

		defer installedFile.Close()
		scriptData := &bytes.Buffer{}
		triggerData := &bytes.Buffer{}
		installedData := &bytes.Buffer{}

		// TODO: Remove the need for this (SBOMs assume it).
		// TODO: We also need SBOM to contain files, not just packages.
		instmw := io.MultiWriter(installedData, installedFile)

		for _, split := range splits {
			if err := func() error {
				scripts, err := split.Scripts()
				if err != nil {
					return err
				}
				defer scripts.Close()
				if _, err := io.Copy(scriptData, scripts); err != nil {
					return err
				}

				triggers, err := split.Triggers()
				if err != nil {
					return err
				}
				defer triggers.Close()
				if _, err := io.Copy(triggerData, triggers); err != nil {
					return err
				}

				installed, err := split.Installed()
				if err != nil {
					return err
				}
				defer installed.Close()
				if _, err := io.Copy(instmw, installed); err != nil {
					return err
				}

				return nil
			}(); err != nil {
				return err
			}
		}

		if err := tw.WriteHeader(&tar.Header{
			Name: "lib/apk/db/scripts.tar",
			Size: int64(scriptData.Len()),
			Mode: 0644,
		}); err != nil {
			return fmt.Errorf("writing scripts.tar header: %w", err)
		}
		if _, err := io.Copy(tw, scriptData); err != nil {
			return fmt.Errorf("writing scripts.tar: %w", err)
		}

		if err := tw.WriteHeader(&tar.Header{
			Name: "lib/apk/db/triggers",
			Size: int64(triggerData.Len()),
			Mode: 0644,
		}); err != nil {
			return fmt.Errorf("writing triggers header: %w", err)
		}
		if _, err := io.Copy(tw, triggerData); err != nil {
			return fmt.Errorf("writing triggers: %w", err)
		}

		if err := tw.WriteHeader(&tar.Header{
			Name: "lib/apk/db/installed",
			Size: int64(installedData.Len()),
			Mode: 0644,
		}); err != nil {
			return fmt.Errorf("writing installed header: %w", err)
		}
		if _, err := io.Copy(tw, installedData); err != nil {
			return fmt.Errorf("writing installed: %w", err)
		}

		// NOTE: Flush() not Close() to avoid tar EOF.
		if err := tw.Flush(); err != nil {
			return fmt.Errorf("flushing tar: %w", err)
		}

		if err := zw.Close(); err != nil {
			return fmt.Errorf("closing gzip: %w", err)
		}

		// TODO: Fanout with WriteAt?
		for _, split := range splits {
			uncompressed, err := split.Uncompressed()
			if err != nil {
				return err
			}
			if _, err := io.Copy(diffid, uncompressed); err != nil {
				return err
			}

			compressed, err := split.Compressed()
			if err != nil {
				return err
			}
			if _, err := io.Copy(zmw, compressed); err != nil {
				return err
			}
		}

		return nil
	}(); err != nil {
		return "", nil, nil, 0, err
	}

	o.Logger().Infof("finished building filesystem in %s", o.WorkDir)

	return w.Name(), diffid, digest, cw.n, nil
}
