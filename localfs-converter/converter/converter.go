// Copyright Project Harbor Authors
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

package converter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/archive/compression"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/content/local"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/images/converter"
	"github.com/containerd/containerd/labels"
	"github.com/containerd/containerd/pkg/cri/constants"
	"github.com/containerd/containerd/platforms"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/containerd/nydus-snapshotter/localfs-converter/remote"

	// "github.com/containerd/nydus-snapshotter/localfs-converter/content"

	"github.com/containerd/nydus-snapshotter/localfs-converter/utils"
	nydusify "github.com/containerd/nydus-snapshotter/pkg/converter"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var logger = logrus.WithField("module", "converter")

const (
	overlayfsSnapshotter = "overlayfs"
	fsVersion            = "6"
	compressor           = "none"
)

type Converter interface {
	Convert(ctx context.Context, source string, manifestDigest digest.Digest, currentLayerDigest digest.Digest, blob *os.File, isLastLayer bool) error

	Merge(ctx context.Context, blobs []string, bootstrap *os.File) error
}

type LocalConverter struct {
	client *containerd.Client
	// key is manifest digest, value is layers' descriptors (manifest.Layers)
	manifestLayersMap map[digest.Digest][]ocispec.Descriptor
	Config            *ConverterConfig
	image             containerd.Image
}

type ConverterConfig struct {
	ContainerdAddress string
	BlobDir           string
	BuilderPath       string
}

func NewLocalConverter(cfg *ConverterConfig) (*LocalConverter, error) {
	client, err := containerd.New(
		cfg.ContainerdAddress,
		containerd.WithDefaultNamespace(constants.K8sContainerdNamespace),
	)
	if err != nil {
		return nil, errors.Wrap(err, "create containerd client")
	}

	localConverter := &LocalConverter{
		client:            client,
		manifestLayersMap: make(map[digest.Digest][]ocispec.Descriptor),
		Config:            cfg,
	}

	return localConverter, nil
}

func (cvt *LocalConverter) Merge(ctx context.Context, blobs []string, bootstrap *os.File) error {
	// return cvt.Driver.Merge(ctx, cvt.pvd, blobs, bootstrap)
	cs := cvt.client.ContentStore()

	_, err := mergeNydusLayers(ctx, cs, blobs, nydusify.MergeOption{
		BuilderPath: cvt.Config.BuilderPath,
		WorkDir:     cvt.Config.BlobDir,
	}, bootstrap)
	if err != nil {
		return errors.Wrap(err, "merge nydus layers")
	}
	return nil
}

func (cvt *LocalConverter) Convert(ctx context.Context, source string, manifestDigest digest.Digest, currentLayerDigest digest.Digest, blob *os.File, isLastLayer bool) error {
	ctx, done, err := cvt.client.WithLease(ctx)
	if err != nil {
		return errors.Wrap(err, "create lease")
	}
	defer done(ctx)

	// check content if current layer exist
	cs := cvt.client.ContentStore()
	if _, err = cs.Info(ctx, currentLayerDigest); err != nil {
		// if ErrNotFound, pull image
		if !strings.Contains(err.Error(), errdefs.ErrNotFound.Error()) {
			return errors.Wrap(err, "get info of layer")
		}
		logger.Infof("pulling image %s", source)
		start := time.Now()
		if err := cvt.Pull(ctx, source); err != nil {
			return errors.Wrap(err, "pull image")
		}
		logger.Infof("pulled image %s, elapse %s", source, time.Since(start))
	}

	descs, ok := cvt.manifestLayersMap[manifestDigest]
	if !ok {
		cs = cvt.client.ContentStore()
		manifest, err := utils.GetManifestbyDigest(ctx, cs, manifestDigest, cvt.image.Target())
		if err != nil {
			return err
		}
		descs, err = utils.GetLayersbyManifestDescriptor(ctx, cs, *manifest)
		if err != nil {
			return err
		}
		cvt.manifestLayersMap[manifestDigest] = descs
	}

	for _, layerDesc := range descs {
		if layerDesc.Digest != currentLayerDigest {
			continue
		}

		// if cvt.cfg.Converter.Async, go routine
		logger.Infof("converting layer %s in image %s", currentLayerDigest, source)
		start := time.Now()
		if _, err := converter.DefaultIndexConvertFunc(convertToNydusLayer(nydusify.PackOption{
			FsVersion:   fsVersion,
			Compressor:  compressor,
			BuilderPath: cvt.Config.BuilderPath,
			WorkDir:     cvt.Config.BlobDir,
		}, blob), true, platforms.All)(
			ctx, cs, layerDesc,
		); err != nil {
			return errors.Wrap(err, "convert oci layer to nydus blob")
		}
		logger.Infof("converted layer %s in image %s, elapse %s", currentLayerDigest, source, time.Since(start))
		break
	}

	return nil
}

func convertToNydusLayer(opt nydusify.PackOption, blob *os.File) converter.ConvertFunc {
	return func(ctx context.Context, cs content.Store, desc ocispec.Descriptor) (*ocispec.Descriptor, error) {
		if !images.IsLayerType(desc.MediaType) {
			return nil, nil
		}

		ra, err := cs.ReaderAt(ctx, desc)
		if err != nil {
			return nil, errors.Wrap(err, "get source blob reader")
		}
		defer ra.Close()
		rdr := io.NewSectionReader(ra, 0, ra.Size())

		// dst, err := content.OpenWriter(ctx, cs, content.WithRef(ref))
		if err != nil {
			return nil, errors.Wrap(err, "open blob writer")
		}
		defer blob.Close()

		tr, err := compression.DecompressStream(rdr)
		if err != nil {
			return nil, errors.Wrap(err, "decompress blob stream")
		}

		digester := digest.SHA256.Digester()
		pr, pw := io.Pipe()
		tw, err := nydusify.Pack(ctx, io.MultiWriter(pw, digester.Hash()), opt, path.Base(blob.Name()))
		if err != nil {
			return nil, errors.Wrap(err, "pack tar to nydus")
		}

		go func() {
			defer pw.Close()
			if _, err := io.Copy(tw, tr); err != nil {
				pw.CloseWithError(err)
				return
			}
			if err := tr.Close(); err != nil {
				pw.CloseWithError(err)
				return
			}
			if err := tw.Close(); err != nil {
				pw.CloseWithError(err)
				return
			}
		}()

		if _, err := io.Copy(blob, pr); err != nil {
			return nil, errors.Wrap(err, "copy nydus blob to content store")
		}

		return &ocispec.Descriptor{}, nil
	}
}

func mergeNydusLayers(ctx context.Context, cs content.Store, blobs []string, opt nydusify.MergeOption, bootstrap *os.File) (*ocispec.Descriptor, error) {
	// Extracts nydus bootstrap from nydus format for each layer.
	layers := []nydusify.BlobLayer{}

	for _, blob := range blobs {
		ra, err := local.OpenReader(blob)
		if err != nil {
			return nil, errors.Wrapf(err, "get reader for blob %q", blob)
		}
		defer ra.Close()
		layers = append(layers, nydusify.BlobLayer{
			Name:     path.Base(blob),
			ReaderAt: ra,
		})
	}

	// Merge all nydus bootstraps into a final nydus bootstrap.
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		if err := nydusify.Merge(ctx, layers, pw, opt); err != nil {
			pw.CloseWithError(errors.Wrapf(err, "merge nydus bootstrap"))
		}
	}()

	// Compress final nydus bootstrap to tar.gz and write into content store.
	var cw = bootstrap
	defer cw.Close()

	uncompressedDgst := digest.SHA256.Digester()
	uncompressed := io.MultiWriter(cw, uncompressedDgst.Hash())
	if _, err := io.Copy(uncompressed, pr); err != nil {
		return nil, errors.Wrapf(err, "copy uncompressed bootstrap into %s", bootstrap.Name())
	}

	if err := cw.Close(); err != nil {
		return nil, errors.Wrap(err, "close gzip writer")
	}

	return &ocispec.Descriptor{}, nil
}

func updateLayerDiffID(ctx context.Context, image ocispec.Descriptor, cs content.Store) error {
	maniDescs, err := utils.GetManifests(ctx, cs, image)
	if err != nil {
		return errors.Wrap(err, "get manifests")
	}

	for _, desc := range maniDescs {
		bytes, err := content.ReadBlob(ctx, cs, desc)
		if err != nil {
			return errors.Wrap(err, "read manifest")
		}

		var manifest ocispec.Manifest
		if err := json.Unmarshal(bytes, &manifest); err != nil {
			return errors.Wrap(err, "unmarshal manifest")
		}

		diffIDs, err := images.RootFS(ctx, cs, manifest.Config)
		if err != nil {
			return errors.Wrap(err, "get diff ids from config")
		}
		if len(manifest.Layers) != len(diffIDs) {
			return fmt.Errorf("unmatched layers between manifest and config: %d != %d", len(manifest.Layers), len(diffIDs))
		}

		for idx, diffID := range diffIDs {
			layerDesc := manifest.Layers[idx]
			info, err := cs.Info(ctx, layerDesc.Digest)
			if err != nil {
				return errors.Wrap(err, "get layer info")
			}
			if info.Labels == nil {
				info.Labels = map[string]string{}
			}
			info.Labels[labels.LabelUncompressed] = diffID.String()
			_, err = cs.Update(ctx, info)
			if err != nil {
				return errors.Wrap(err, "update layer label")
			}
		}
	}

	return nil
}

func (cvt *LocalConverter) Pull(ctx context.Context, ref string) error {
	resolver := remote.NewResolver(remote.NewDockerConfigCredFunc())

	// TODO: enable configuring the target platforms.
	platformMatcher := utils.ExcludeNydusPlatformComparer{MatchComparer: platforms.All}

	opts := []containerd.RemoteOpt{
		// TODO: sets max concurrent downloaded layer limit by containerd.WithMaxConcurrentDownloads.
		containerd.WithPlatformMatcher(platformMatcher),
		containerd.WithImageHandler(images.HandlerFunc(
			func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
				if images.IsLayerType(desc.MediaType) {
					logger.Debugf("pulling layer %s", desc.Digest)
				}
				return nil, nil
			},
		)),
		containerd.WithResolver(resolver),
	}

	// Pull the source image from remote registry.
	image, err := cvt.client.Fetch(ctx, ref, opts...)
	if err != nil {
		return errors.Wrap(err, "pull source image")
	}

	// Write a diff id label of layer in content store for simplifying
	// diff id calculation to speed up the conversion.
	// See: https://github.com/containerd/containerd/blob/e4fefea5544d259177abb85b64e428702ac49c97/images/diffid.go#L49
	if err := updateLayerDiffID(ctx, image.Target, cvt.client.ContentStore()); err != nil {
		return errors.Wrap(err, "update layer diff id")
	}

	cvt.image = containerd.NewImageWithPlatform(cvt.client, image, platformMatcher)

	return nil
}
