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

package layer

import (
	"archive/tar"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	// Import is necessary for go-digest.
	_ "crypto/sha256"

	"github.com/apex/log"
	gzip "github.com/klauspost/pgzip"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/image-spec/identity"
	"github.com/opencontainers/umoci/oci/cas"
	"github.com/opencontainers/umoci/oci/casext"
	iconv "github.com/opencontainers/umoci/oci/config/convert"
	"github.com/opencontainers/umoci/pkg/idtools"
	"github.com/opencontainers/umoci/pkg/system"
	"github.com/pkg/errors"
)

// CacheLayer places a layer identified by its chainID into the cache
func CacheLayer(layer io.Reader, chainID digest.Digest, opt *CacheOptions) (bool, error) {
	// Place layer in layersPath/algo/hash if it's not already there
	algo := chainID.Algorithm()
	hash := chainID.Hex()
	cachePath := filepath.Join(opt.CachePath, algo.String())
	cacheLayerPath := filepath.Join(cachePath, hash)

	_, err := os.Lstat(cacheLayerPath)
	if err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(cachePath, 0755); err != nil && !os.IsExist(err) {
			return false, errors.Wrap(err, "mkdir layers")
		}
		log.Infof("created cache layers: %s", cachePath)
	} else if err != nil {
		return false, errors.Wrapf(err, "detecting layers")
	}

	var unpackOptions UnpackOptions
	if opt != nil {
		unpackOptions.MapOptions.Rootless = opt.MapOptions.Rootless
		unpackOptions.MapOptions.UIDMappings = opt.MapOptions.UIDMappings
		unpackOptions.MapOptions.GIDMappings = opt.MapOptions.GIDMappings
	}

	te := NewTarExtractor(unpackOptions)
	tr := tar.NewReader(layer)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, errors.Wrap(err, "read next entry")
		}
		if err := te.UnpackEntry(cacheLayerPath, hdr, tr); err != nil {
			return false, errors.Wrapf(err, "cache entry: %s", hdr.Name)
		}
	}
	return false, nil
}

// CacheManifest extracts all of the layers in the given manifest, as well as
// generating a runtime bundle and configuration. 
func CacheManifest(ctx context.Context, engine cas.Engine, bundle string, manifest ispec.Manifest, opt *CacheOptions) (err error) {
	// Create the bundle directory. We only error out if config.json 
	// already exists, because we cannot be sure that the user intended us to
	// extract over an existing bundle.
	if err := os.MkdirAll(bundle, 0755); err != nil {
		return errors.Wrap(err, "mkdir bundle")
	}
	// We change the mode of the bundle directory to 0700. A user can easily
	// change this after-the-fact, but we do this explicitly to avoid cases
	// where an unprivileged user could recurse into an otherwise unsafe image
	// (giving them potential root access through setuid binaries for example).
	if err := os.Chmod(bundle, 0700); err != nil {
		return errors.Wrap(err, "chmod bundle 0700")
	}

	manifestPath := filepath.Join(bundle, "manifest.json")
	_, err = os.Lstat(manifestPath)
	if err == nil {
		if !opt.Force {
			return errors.Errorf("manifest.json already exists in %s", bundle)
		}
	} else if !os.IsNotExist(err) {
		return errors.Wrap(err, "problem accessing bundle config")
	}

	// Generate a manifest file from ispec.Image.
	manifestFile, err := os.Create(manifestPath)
	if err != nil {
		return errors.Wrap(err, "open manifest.json")
	}
	defer manifestFile.Close()

	enc := json.NewEncoder(manifestFile)
	enc.SetIndent("", "\t")
	enc.Encode(manifest)

	runCfgPath := filepath.Join(bundle, "runtime-config.json")
	if _, err := os.Lstat(runCfgPath); !os.IsNotExist(err) {
		if err != nil {
			return errors.Wrap(err, "problem accessing bundle runtime-config")
		}
	}

	imgCfgPath := filepath.Join(bundle, "image-config.json")
	if _, err := os.Lstat(imgCfgPath); !os.IsNotExist(err) {
		if err != nil {
			return errors.Wrap(err, "problem accessing bundle image-config")
		}
	}

	_, err = os.Lstat(opt.CachePath)
	if err == nil {
		log.Infof("using existing cache layers: %s", opt.CachePath)
	} else if os.IsNotExist(err) {
		if err := os.Mkdir(opt.CachePath, 0755); err != nil && !os.IsExist(err) {
			return errors.Wrap(err, "mkdir layers")
		}
		log.Infof("created cache layers: %s", opt.CachePath)
	} else {
		return errors.Wrapf(err, "detecting layers")
	}

	log.Infof("cache layers: %s", opt.CachePath)
	if err := CacheLayers(ctx, engine, manifest, opt); err != nil {
		return errors.Wrap(err, "cache layers")
	}

	imgCfgFile, err := os.Create(imgCfgPath)
	if err != nil {
		return errors.Wrap(err, "open image-config.json")
	}
	defer imgCfgFile.Close()

	// Generate a runtime configuration file from ispec.Image.
	runCfgFile, err := os.Create(runCfgPath)
	if err != nil {
		return errors.Wrap(err, "open runtime-config.json")
	}
	defer runCfgFile.Close()

	if err := CacheRuntimeJSON(ctx, engine, runCfgFile, imgCfgFile, manifest, opt); err != nil {
		return errors.Wrap(err, "cache config.json")
	}
	return nil
}

// CacheLayers extracts all of the layers in the given manifest.
// Some verification is done during image extraction.
func CacheLayers(ctx context.Context, engine cas.Engine, manifest ispec.Manifest, opt *CacheOptions) (err error) {
	engineExt := casext.NewEngine(engine)

	// Make sure that the owner is correct.
	rootUID, err := idtools.ToHost(0, opt.MapOptions.UIDMappings)
	if err != nil {
		return errors.Wrap(err, "ensure rootuid has mapping")
	}
	rootGID, err := idtools.ToHost(0, opt.MapOptions.GIDMappings)
	if err != nil {
		return errors.Wrap(err, "ensure rootgid has mapping")
	}
	if err := os.Lchown(opt.CachePath, rootUID, rootGID); err != nil {
		return errors.Wrap(err, "chown layers")
	}

	// Currently, many different images in the wild don't specify what the
	// atime/mtime of the root directory is. This is a huge pain because it
	// means that we can't ensure consistent caching. In order to get around
	// this, we first set the mtime of the root directory to the Unix epoch
	// (which is as good of an arbitrary choice as any).
	epoch := time.Unix(0, 0)
	if err := system.Lutimes(opt.CachePath, epoch, epoch); err != nil {
		return errors.Wrap(err, "set initial root time")
	}

	// In order to verify the DiffIDs as we extract layers, we have to get the
	// .Config blob first. But we can't extract it (generate the runtime
	// config) until after we have the full rootfs generated.
	configBlob, err := engineExt.FromDescriptor(ctx, manifest.Config)
	if err != nil {
		return errors.Wrap(err, "get config blob")
	}
	defer configBlob.Close()
	if configBlob.Descriptor.MediaType != ispec.MediaTypeImageConfig {
		return errors.Errorf("cache layers: config blob is not correct mediatype %s: %s",
				     ispec.MediaTypeImageConfig, configBlob.Descriptor.MediaType)
	}
	config, ok := configBlob.Data.(ispec.Image)
	if !ok {
		// Should _never_ be reached.
		return errors.Errorf("[internal error] unknown config blob type: %s",
				     configBlob.Descriptor.MediaType)
	}

	// We can't understand non-layer images.
	if config.RootFS.Type != "layers" {
		return errors.Errorf("cache layers: config: unsupported rootfs.type: %s",
				     config.RootFS.Type)
	}

	var chain []digest.Digest

	// Layer extraction.
	for idx, layerDescriptor := range manifest.Layers {
		layerDiffID := config.RootFS.DiffIDs[idx]
		log.Infof("cache layer: %s", layerDescriptor.Digest)

		chain = append(chain, layerDiffID)
		chainID := identity.ChainID(chain)

		layerBlob, err := engineExt.FromDescriptor(ctx, layerDescriptor)
		if err != nil {
			return errors.Wrap(err, "get layer blob")
		}
		defer layerBlob.Close()
		if !isLayerType(layerBlob.Descriptor.MediaType) {
			return errors.Errorf("cache layers: layer %s: blob is not correct mediatype: %s", layerBlob.Descriptor.Digest, layerBlob.Descriptor.MediaType)
		}
		layerData, ok := layerBlob.Data.(io.ReadCloser)
		if !ok {
			// Should _never_ be reached.
			return errors.Errorf("[internal error] layerBlob was not an io.ReadCloser")
		}

		layerRaw := layerData
		if needsGunzip(layerBlob.Descriptor.MediaType) {
			// We have to extract a gzip'd version of the above layer. Also note
			// that we have to check the DiffID we're extracting (which is the
			// sha256 sum of the *uncompressed* layer).
			layerRaw, err = gzip.NewReader(layerData)
			if err != nil {
				return errors.Wrap(err, "create gzip reader")
			}
		}

		layerDigester := digest.SHA256.Digester()
		layer := io.TeeReader(layerRaw, layerDigester.Hash())

		alreadyCached, err := CacheLayer(layer, chainID, opt)
		if err != nil {
			return errors.Wrap(err, "cache layer")
		}

		if !alreadyCached {
			// Different tar implementations can have different levels of redundant
			// padding and other similar weird behaviours. While on paper they are
			// all entirely valid archives, Go's tar.Reader implementation doesn't
			// guarantee that the entire stream will be consumed (which can result
			// in the later diff_id check failing because the digester didn't get
			// the whole uncompressed stream). Just blindly consume anything left
			// in the layer.
			if n, err := system.Copy(ioutil.Discard, layer); err != nil {
				return errors.Wrap(err, "discard trailing archive bits")
			} else if n != 0 {
				log.Debugf("unpack manifest: layer %s: ignoring %d trailing 'junk' bytes in the tar stream -- probably from GNU tar", layerDescriptor.Digest, n)
			}
			// Same goes for compressed layers -- it seems like some gzip
			// implementations add trailing NUL bytes, which Go doesn't slurp up.
			// Just eat up the rest of the remaining bytes and discard them.
			//
			// FIXME: We use layerData here because pgzip returns io.EOF from
			// WriteTo, which causes havoc with system.Copy. Ideally we would use
			// layerRaw. See <https://github.com/klauspost/pgzip/issues/38>.
			if n, err := system.Copy(ioutil.Discard, layerData); err != nil {
				return errors.Wrap(err, "discard trailing raw bits")
			} else if n != 0 {
				log.Warnf("cache manifest: layer %s: ignoring %d trailing 'junk' bytes in the blob stream " +
					  "-- this may indicate a bug in the tool which built this image",
					  layerDescriptor.Digest, n)
			}
			if err := layerData.Close(); err != nil {
				return errors.Wrap(err, "close layer data")
			}

			layerDigest := layerDigester.Digest()
			if layerDigest != layerDiffID {
				return errors.Errorf("cache manifest: layer %s: diffid mismatch: got %s expected %s",
						     layerDescriptor.Digest, layerDigest, layerDiffID)
			}
		}
	}

	return nil
}

// CacheRuntimeJSON converts a given manifest's configuration to a runtime
// configuration and writes it to the given writer. If rootfs is specified, it
// is sourced during the configuration generation (for conversion of
// Config.User and other similar jobs -- which will error out if the user could
// not be parsed). If rootfs is not specified (is an empty string) then all
// conversions that require sourcing the rootfs will be set to their default
// values.
//
func CacheRuntimeJSON(ctx context.Context, engine cas.Engine, runCfgFile io.Writer, imgCfgFile io.Writer, manifest ispec.Manifest, opt *CacheOptions) error {
	engineExt := casext.NewEngine(engine)

	var mapOptions MapOptions
	if opt != nil {
		mapOptions = opt.MapOptions
	}

	// In order to verify the DiffIDs as we extract layers, we have to get the
	// .Config blob first. But we can't extract it (generate the runtime
	// config) until after we have the full rootfs generated.
	configBlob, err := engineExt.FromDescriptor(ctx, manifest.Config)
	if err != nil {
		return errors.Wrap(err, "get config blob")
	}
	defer configBlob.Close()
	if configBlob.Descriptor.MediaType != ispec.MediaTypeImageConfig {
		return errors.Errorf("cache manifest: config blob is not correct mediatype %s: %s", ispec.MediaTypeImageConfig, configBlob.Descriptor.MediaType)
	}
	config, ok := configBlob.Data.(ispec.Image)
	if !ok {
		// Should _never_ be reached.
		return errors.Errorf("[internal error] unknown config blob type: %s", configBlob.Descriptor.MediaType)
	}

	// Save the image-config.json.
	enc := json.NewEncoder(imgCfgFile)
	enc.SetIndent("", "\t")
	enc.Encode(configBlob)

	spec, err := iconv.ToRuntimeSpec(opt.CachePath, config)
	if err != nil {
		return errors.Wrap(err, "generate config.json")
	}

	// Add UIDMapping / GIDMapping options.
	if len(mapOptions.UIDMappings) > 0 || len(mapOptions.GIDMappings) > 0 {
		var namespaces []rspec.LinuxNamespace
		for _, ns := range spec.Linux.Namespaces {
			if ns.Type == "user" {
				continue
			}
			namespaces = append(namespaces, ns)
		}
		spec.Linux.Namespaces = append(namespaces, rspec.LinuxNamespace{
			Type: "user",
		})
	}
	spec.Linux.UIDMappings = mapOptions.UIDMappings
	spec.Linux.GIDMappings = mapOptions.GIDMappings
	if mapOptions.Rootless {
		if err := iconv.ToRootless(&spec); err != nil {
			return errors.Wrap(err, "convert spec to rootless")
		}
	}
	spec.Root.Path, _ = filepath.Abs(opt.CachePath)

	// Save the runtime-config.json.
	enc = json.NewEncoder(runCfgFile)
	enc.SetIndent("", "\t")
	return errors.Wrap(enc.Encode(spec), "write config.json")
}
