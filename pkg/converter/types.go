/*
 * Copyright (c) 2022. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"github.com/containerd/containerd/content"
	"github.com/opencontainers/go-digest"
)

type Layer struct {
	// Digest represents the hash of whole tar blob.
	Digest digest.Digest
	// ReaderAt holds the reader of whole tar blob.
	ReaderAt content.ReaderAt
}

type BlobLayer struct {
	// Digest represents the hash of whole tar blob.
	Name string
	// ReaderAt holds the reader of whole tar blob.
	ReaderAt content.ReaderAt
}

type PackOption struct {
	// WorkDir is used as the work directory during layer pack.
	WorkDir string
	// BuilderPath holds the path of `nydus-image` binary tool.
	BuilderPath string
	// FsVersion specifies nydus RAFS format version, possible
	// values: `5`, `6` (EROFS-compatible), default is `5`.
	FsVersion string
	// ChunkDictPath holds the bootstrap path of chunk dict image.
	ChunkDictPath string
	// PrefetchPatterns holds file path pattern list want to prefetch.
	PrefetchPatterns string
	// Compressor specifies nydus blob compression algorithm.
	Compressor string
}

type MergeOption struct {
	// WorkDir is used as the work directory during layer merge.
	WorkDir string
	// BuilderPath holds the path of `nydus-image` binary tool.
	BuilderPath string
	// ChunkDictPath holds the bootstrap path of chunk dict image.
	ChunkDictPath string
	// PrefetchPatterns holds file path pattern list want to prefetch.
	PrefetchPatterns string
	// WithTar puts bootstrap into a tar stream (no gzip).
	WithTar bool
}

type UnpackOption struct {
	// WorkDir is used as the work directory during layer unpack.
	WorkDir string
	// BuilderPath holds the path of `nydus-image` binary tool.
	BuilderPath string
}
