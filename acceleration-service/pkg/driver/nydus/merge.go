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

package nydus

import (
	"context"
	"io"
	"os"
	"path"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/content/local"
	"github.com/containerd/containerd/log"
	nydusify "github.com/containerd/nydus-snapshotter/pkg/converter"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

func mergeNydusLayers(ctx context.Context, cs content.Store, blobs []string, opt nydusify.MergeOption, fsVersion string, bootstrap *os.File) (*ocispec.Descriptor, error) {
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
		log.G(ctx).Infof("====zhaoshang io.Copy(uncompressed, pr) fail =====  %#+v ", uncompressed)
		return nil, errors.Wrapf(err, "copy uncompressed bootstrap into %s", bootstrap.Name())
	}

	if err := cw.Close(); err != nil {
		return nil, errors.Wrap(err, "close gzip writer")
	}
	log.G(ctx).Infof("====zhaoshang mergeNydusLayers success =====  %#+v ", uncompressed)
	return &ocispec.Descriptor{}, nil
}
