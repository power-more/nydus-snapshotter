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

	"github.com/containerd/containerd/content"
	nydusify "github.com/containerd/nydus-snapshotter/pkg/converter"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

func mergeNydusLayers(ctx context.Context, cs content.Store, descs []ocispecs.Descriptor, opt nydusify.MergeOption, fsVersion string, bootstrap *os.File) (*ocispec.Descriptor, error) {
	// Extracts nydus bootstrap from nydus format for each layer.
	layers := []nydusify.Layer{}

	var chainID digest.Digest
	for _, blobDesc := range descs {
		ra, err := cs.ReaderAt(ctx, blobDesc)
		if err != nil {
			return nil, errors.Wrapf(err, "get reader for blob %q", blobDesc.Digest)
		}
		defer ra.Close()
		layers = append(layers, nydusify.Layer{
			Digest:   blobDesc.Digest,
			ReaderAt: ra,
		})
		if chainID == "" {
			chainID = identity.ChainID([]digest.Digest{blobDesc.Digest})
		} else {
			chainID = identity.ChainID([]digest.Digest{chainID, blobDesc.Digest})
		}
	}

	// Merge all nydus bootstraps into a final nydus bootstrap.
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		if err := nydusify.Merge(ctx, layers, pw, nydusify.MergeOption{
			WithTar: false,
		}); err != nil {
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
