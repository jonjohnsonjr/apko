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
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
)

func maybeGenerateVendorReleaseFile(
	fsys apkfs.FullFS, ic *types.ImageConfiguration,
) error {
	if ic.OSRelease.ID == "" || ic.OSRelease.VersionID == "" {
		return nil
	}

	path := filepath.Join("etc", fmt.Sprintf("%s-release", ic.OSRelease.ID))

	_, err := fsys.Stat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	w, err := fsys.Create(path)
	if err != nil {
		return err
	}
	defer w.Close()

	_, err = fmt.Fprintf(w, "%s\n", ic.OSRelease.VersionID)
	if err != nil {
		return err
	}

	return nil
}

func (di *buildImplementation) GenerateOSRelease(
	fsys apkfs.FullFS, o *options.Options, ic *types.ImageConfiguration,
) error {
	path := filepath.Join("etc", "os-release")

	osReleaseExists := true
	if _, err := fsys.Stat(path); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		o.Logger().Warnf("did not find /etc/os-release at %s", path)
		osReleaseExists = false
	}

	// If /etc/os-release does not exist, return an error that it already exists.
	// However, if the user is requesting an override, write over it anyway.
	// TODO: better than checking for "apko-generated image"
	if osReleaseExists && ic.OSRelease.Name == "apko-generated image" {
		return ErrOSReleaseAlreadyPresent
	}

	w, err := fsys.Create(path)
	if err != nil {
		return err
	}
	defer w.Close()

	if ic.OSRelease.ID != "" {
		if ic.OSRelease.ID == "unknown" {
			o.Logger().Warnf("distro ID not specified and /etc/os-release does not already exist")
		}
		_, err := fmt.Fprintf(w, "ID=%s\n", ic.OSRelease.ID)
		if err != nil {
			return err
		}
	}

	if ic.OSRelease.Name != "" {
		_, err := fmt.Fprintf(w, "NAME=\"%s\"\n", ic.OSRelease.Name)
		if err != nil {
			return err
		}
	}

	if ic.OSRelease.PrettyName != "" {
		_, err := fmt.Fprintf(w, "PRETTY_NAME=\"%s\"\n", ic.OSRelease.PrettyName)
		if err != nil {
			return err
		}
	}

	if ic.OSRelease.VersionID != "" {
		_, err := fmt.Fprintf(w, "VERSION_ID=%s\n", ic.OSRelease.VersionID)
		if err != nil {
			return err
		}
	}

	if ic.OSRelease.HomeURL != "" {
		_, err := fmt.Fprintf(w, "HOME_URL=\"%s\"\n", ic.OSRelease.HomeURL)
		if err != nil {
			return err
		}
	}

	if ic.OSRelease.BugReportURL != "" {
		_, err := fmt.Fprintf(w, "BUG_REPORT_URL=\"%s\"\n", ic.OSRelease.BugReportURL)
		if err != nil {
			return err
		}
	}

	if err := maybeGenerateVendorReleaseFile(fsys, ic); err != nil {
		return err
	}

	return nil
}

func CreateOSRelease(ic *types.ImageConfiguration) string {
	lines := []string{}

	if ic.OSRelease.ID != "" {
		lines = append(lines, fmt.Sprintf("ID=%s\n", ic.OSRelease.ID))
	}

	if ic.OSRelease.Name != "" {
		lines = append(lines, fmt.Sprintf("NAME=%q\n", ic.OSRelease.Name))
	}

	if ic.OSRelease.PrettyName != "" {
		lines = append(lines, fmt.Sprintf("PRETTY_NAME=%q\n", ic.OSRelease.PrettyName))
	}

	if ic.OSRelease.VersionID != "" {
		lines = append(lines, fmt.Sprintf("VERSION_ID=%s\n", ic.OSRelease.VersionID))
	}

	if ic.OSRelease.HomeURL != "" {
		lines = append(lines, fmt.Sprintf("HOME_URL=%q\n", ic.OSRelease.HomeURL))
	}

	if ic.OSRelease.BugReportURL != "" {
		lines = append(lines, fmt.Sprintf("BUG_REPORT_URL=%q\n", ic.OSRelease.BugReportURL))
	}

	return strings.Join(lines, "")
}

// We assume it does not exist already.
func AppendOSRelease(tw *tar.Writer, ic *types.ImageConfiguration) error {
	path := filepath.Join("etc", "os-release")

	w := &bytes.Buffer{}

	if ic.OSRelease.ID != "" {
		_, err := fmt.Fprintf(w, "ID=%s\n", ic.OSRelease.ID)
		if err != nil {
			return err
		}
	}

	if ic.OSRelease.Name != "" {
		_, err := fmt.Fprintf(w, "NAME=\"%s\"\n", ic.OSRelease.Name)
		if err != nil {
			return err
		}
	}

	if ic.OSRelease.PrettyName != "" {
		_, err := fmt.Fprintf(w, "PRETTY_NAME=\"%s\"\n", ic.OSRelease.PrettyName)
		if err != nil {
			return err
		}
	}

	if ic.OSRelease.VersionID != "" {
		_, err := fmt.Fprintf(w, "VERSION_ID=%s\n", ic.OSRelease.VersionID)
		if err != nil {
			return err
		}
	}

	if ic.OSRelease.HomeURL != "" {
		_, err := fmt.Fprintf(w, "HOME_URL=\"%s\"\n", ic.OSRelease.HomeURL)
		if err != nil {
			return err
		}
	}

	if ic.OSRelease.BugReportURL != "" {
		_, err := fmt.Fprintf(w, "BUG_REPORT_URL=\"%s\"\n", ic.OSRelease.BugReportURL)
		if err != nil {
			return err
		}
	}

	hdr := tar.Header{
		Name: path,
		Size: int64(w.Len()),
	}
	if err := tw.WriteHeader(&hdr); err != nil {
		return err
	}
	if _, err := io.Copy(tw, w); err != nil {
		return err
	}

	if err := appendVendorReleaseFile(tw, ic); err != nil {
		return err
	}

	return nil
}

func appendVendorReleaseFile(tw *tar.Writer, ic *types.ImageConfiguration) error {
	if ic.OSRelease.ID == "" || ic.OSRelease.VersionID == "" {
		return nil
	}

	path := filepath.Join("etc", fmt.Sprintf("%s-release", ic.OSRelease.ID))

	w := &bytes.Buffer{}

	if _, err := fmt.Fprintf(w, "%s\n", ic.OSRelease.VersionID); err != nil {
		return err
	}

	hdr := tar.Header{
		Name: path,
		Size: int64(w.Len()),
	}
	if err := tw.WriteHeader(&hdr); err != nil {
		return err
	}
	if _, err := io.Copy(tw, w); err != nil {
		return err
	}

	return nil
}
