// Copyright 2023 Chainguard, Inc.
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
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/chainguard-dev/go-apk/pkg/apk"
)

// TODO: Restructure packages to avoid duplicating this stuff.
type lock struct {
	Version  string       `json:"version"`
	Contents lockContents `json:"contents"`
}

type lockContents struct {
	Packages []lockPkg `json:"packages"`
}

type lockPkg struct {
	Name         string                  `json:"name"`
	URL          string                  `json:"url"`
	Version      string                  `json:"version"`
	Architecture string                  `json:"architecture"`
	Signature    lockPkgRangeAndChecksum `json:"signature"`
	Control      lockPkgRangeAndChecksum `json:"control"`
	Data         lockPkgRangeAndChecksum `json:"data"`
}

type lockPkgRangeAndChecksum struct {
	Range    string `json:"range"`
	Checksum string `json:"checksum"`
}

func parseLockfile(name string) ([]*apk.RepositoryPackage, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	lock := lock{}

	if err := json.NewDecoder(f).Decode(&lock); err != nil {
		return nil, err
	}

	toInstall := make([]*apk.RepositoryPackage, 0, len(lock.Contents.Packages))
	for _, pkg := range lock.Contents.Packages {
		before, _, ok := strings.Cut(pkg.URL, "/"+pkg.Name)
		if !ok {
			return nil, fmt.Errorf("failed to interpret %q in %q as repo", pkg.URL, pkg.Name)
		}
		repo := (&apk.Repository{
			URI: before,
		}).WithIndex(nil)

		// TODO
		apkg := apk.Package{
			Name:    pkg.Name,
			Version: pkg.Version,
			Arch:    pkg.Architecture,
		}
		toInstall = append(toInstall, apk.NewRepositoryPackage(&apkg, repo))
	}

	return toInstall, nil
}
