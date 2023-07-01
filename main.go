// Copyright 2022, 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"log"

	"chainguard.dev/apko/internal/cli"
	"github.com/jonjohnsonjr/mane/trace"
)

func main() {
	if err := trace.Main(context.Background(), cli.New().ExecuteContext); err != nil {
		log.Fatalf("error during command execution: %v", err)
	}
}
