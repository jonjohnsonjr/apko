package build

import (
	"archive/tar"
	"fmt"
	"path/filepath"

	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
	"golang.org/x/sys/unix"
)

var devices = []struct {
	path  string
	major uint32
	minor uint32
}{
	{"/dev/zero", 1, 5},
	{"/dev/urandom", 1, 9},
	{"/dev/null", 1, 3},
	{"/dev/random", 1, 8},
	{"/dev/console", 5, 1},
}

func (di *buildImplementation) InstallCharDevices(fsys apkfs.FullFS) error {
	for _, dev := range devices {
		if _, err := fsys.Stat(dev.path); err == nil {
			continue
		}
		dir := filepath.Dir(dev.path)
		if err := fsys.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
		if err := fsys.Mknod(dev.path, unix.S_IFCHR, int(unix.Mkdev(dev.major, dev.minor))); err != nil {
			return fmt.Errorf("creating character device %s: %w", dev.path, err)
		}
	}
	return nil
}

func AppendCharDevices(tw *tar.Writer) error {
	dir := &tar.Header{
		Name:     "/dev",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}
	if err := tw.WriteHeader(dir); err != nil {
		return fmt.Errorf("creating /dev: %w", err)
	}

	for _, dev := range devices {
		hdr := &tar.Header{
			Name:     dev.path,
			Typeflag: tar.TypeChar,
			Devmajor: int64(dev.major),
			Devminor: int64(dev.minor),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("creating character device %s: %w", dev.path, err)
		}
	}
	return nil
}
