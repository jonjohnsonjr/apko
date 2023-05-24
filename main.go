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
	"os"
	"runtime/pprof"
	"runtime/trace"

	"chainguard.dev/apko/internal/cli"
)

func main() {
	if pp := os.Getenv("PPROF"); pp != "" {
		if pp != "" {
			f, err := os.Create(pp)
			if err != nil {
				log.Fatal(err)
			}
			pprof.StartCPUProfile(f)
			defer pprof.StopCPUProfile()
		}
	}
	ctx := context.Background()
	if tr := os.Getenv("TRACE"); tr != "" {
		f, err := os.Create(tr)
		if err != nil {
			log.Fatalf("failed to create trace output file: %v", err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				log.Fatalf("failed to close trace file: %v", err)
			}
		}()

		if err := trace.Start(f); err != nil {
			log.Fatal(err)
		}
		defer trace.Stop()

		ctx2, task := trace.NewTask(ctx, "apko")
		defer task.End()

		ctx = ctx2
	}
	if err := cli.New().ExecuteContext(ctx); err != nil {
		log.Fatalf("error during command execution: %v", err)
	}
}
