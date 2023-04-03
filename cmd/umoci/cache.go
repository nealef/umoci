/*
 * umoci: Umoci Modifies Open Containers' Images
 * Copyright (C) 2016-2020 SUSE LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"path/filepath"

	"github.com/opencontainers/umoci"
	"github.com/opencontainers/umoci/oci/cas/dir"
	"github.com/opencontainers/umoci/oci/casext"
	"github.com/opencontainers/umoci/oci/layer"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var cacheCommand = uxRemap(cli.Command{
	Name:  "cache",
	Usage: "caches a reference into an OCI runtime bundle",
	ArgsUsage: `--image <image-path>[:<tag>] <bundle> [--cache <cache-path>]

Where "<image-path>" is the path to the OCI image, "<tag>" is the name of the
tagged image to cache (if not specified, defaults to "latest"), "<bundle>"
is the destination of the metadata (<bundle>/<image>/<tag>), and "<cache>" is 
where the expanded layers are placed (defaults to /var/local/layer-cache).`,

	// cache reads manifest information.
	Category: "image",

	Flags: []cli.Flag{
		cli.StringFlag {
			Name: "cache", 
			Usage: "Path to where layers are cached (default /var/local/layer-cache)",
		},
		cli.BoolFlag {
			Name: "force",
			Usage: "Overwrite any existing metadata files",
		},
	},

	Action: cache,

	Before: func(ctx *cli.Context) error {
		if ctx.NArg() != 1 {
			return errors.Errorf("invalid number of positional arguments: expected <bundle>")
		}
		if ctx.Args().First() == "" {
			return errors.Errorf("bundle path cannot be empty")
		}
		ctx.App.Metadata["bundle"] = ctx.Args().First()
		return nil
	},
})

func cache(ctx *cli.Context) error {
	imagePath := ctx.App.Metadata["--image-path"].(string)
	fromName := ctx.App.Metadata["--image-tag"].(string)
	bundlePath := filepath.Join(ctx.App.Metadata["bundle"].(string), imagePath, fromName)

	var cacheOptions layer.CacheOptions
	var meta umoci.Meta
	meta.Version = umoci.MetaVersion

	// Parse and set up the mapping options.
	err := umoci.ParseIdmapOptions(&meta, ctx)
	if err != nil {
		return err
	}

	cacheOptions.MapOptions = meta.MapOptions
	if ctx.IsSet("cache") {
		cacheOptions.CachePath = ctx.String("cache")
	} else {
		cacheOptions.CachePath = "/var/local/layer-cache"
	}
	cacheOptions.Force = ctx.Bool("force")

	// Get a reference to the CAS.
	engine, err := dir.Open(imagePath)
	if err != nil {
		return errors.Wrap(err, "open CAS")
	}
	engineExt := casext.NewEngine(engine)
	defer engine.Close()
	return umoci.Cache(engineExt, fromName, bundlePath, cacheOptions)
}
