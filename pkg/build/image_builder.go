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
	"fmt"
	"io"
	"path/filepath"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/s6"
)

func (di *buildImplementation) ValidateImageConfiguration(ic *types.ImageConfiguration) error {
	if err := ic.Validate(); err != nil {
		return fmt.Errorf("failed to validate configuration: %w", err)
	}
	return nil
}

func (di *buildImplementation) WriteSupervisionTree(
	s6context *s6.Context, imageConfig *types.ImageConfiguration,
) error {
	// write service supervision tree
	s6m := make(map[interface{}]interface{}, len(imageConfig.Entrypoint.Services))
	for k, v := range imageConfig.Entrypoint.Services {
		s6m[k] = v
	}
	if err := s6context.WriteSupervisionTree(s6m); err != nil {
		return fmt.Errorf("failed to write supervision tree: %w", err)
	}
	return nil
}

// Inlined form of WriteSupervisionTree.
func AppendSupervisionTree(tw *tar.Writer, ic *types.ImageConfiguration) error {
	for service, command := range ic.Entrypoint.Services {
		svcdir := filepath.Join("sv", service)

		dir := &tar.Header{
			Name:     svcdir,
			Typeflag: tar.TypeDir,
			Mode:     0777,
		}
		if err := tw.WriteHeader(dir); err != nil {
			return fmt.Errorf("could not make supervision directory %q: %w", svcdir, err)
		}

		w := &bytes.Buffer{}
		fmt.Fprintf(w, "#!/bin/execlineb\n%s\n", command)

		filename := filepath.Join(svcdir, "run")
		hdr := &tar.Header{
			Name: filename,
			Mode: 0755,
			Size: int64(w.Len()),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("could not create runfile %q: %w", filename, err)
		}
		if _, err := io.Copy(tw, w); err != nil {
			return fmt.Errorf("could not write runfile %q: %w", filename, err)
		}
	}

	return nil
}
