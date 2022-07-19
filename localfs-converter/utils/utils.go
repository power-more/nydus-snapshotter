package utils

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/platforms"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const ManifestOSFeatureNydus = "nydus.remoteimage.v1"

func GetManifestbyDigest(ctx context.Context, provider content.Provider, target digest.Digest, desc ocispec.Descriptor) (*ocispec.Descriptor, error) {
	switch desc.MediaType {
	case images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest:
		if desc.Digest == target {
			return &desc, nil
		}
	case images.MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex:
		p, err := content.ReadBlob(ctx, provider, desc)
		if err != nil {
			return nil, err
		}

		var index ocispec.Index
		if err := json.Unmarshal(p, &index); err != nil {
			return nil, err
		}

		for _, idesc := range index.Manifests {
			if idesc.Digest == target {
				return &idesc, nil
			}
		}
	}

	return nil, fmt.Errorf("can not get manifest descriptor by digest %+v from descriptor %+v", target, desc)
}

func GetLayersbyManifestDescriptor(ctx context.Context, provider content.Provider, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	if desc.MediaType != images.MediaTypeDockerSchema2Manifest && desc.MediaType != ocispec.MediaTypeImageManifest {
		return nil, fmt.Errorf("descriptor %+v is not manifest descriptor", desc)
	}

	p, err := content.ReadBlob(ctx, provider, desc)
	if err != nil {
		return nil, err
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(p, &manifest); err != nil {
		return nil, err
	}

	return manifest.Layers, nil
}

func GetManifests(ctx context.Context, provider content.Provider, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	var descs []ocispec.Descriptor
	switch desc.MediaType {
	case images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest:
		descs = append(descs, desc)
	case images.MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex:
		p, err := content.ReadBlob(ctx, provider, desc)
		if err != nil {
			return nil, err
		}

		var index ocispec.Index
		if err := json.Unmarshal(p, &index); err != nil {
			return nil, err
		}

		descs = append(descs, index.Manifests...)
	default:
		return nil, nil
	}

	return descs, nil
}

type ExcludeNydusPlatformComparer struct {
	platforms.MatchComparer
}

func (c ExcludeNydusPlatformComparer) Match(platform ocispec.Platform) bool {
	for _, key := range platform.OSFeatures {
		if key == ManifestOSFeatureNydus {
			return false
		}
	}
	return c.MatchComparer.Match(platform)
}

func (c ExcludeNydusPlatformComparer) Less(a, b ocispec.Platform) bool {
	return c.MatchComparer.Less(a, b)
}
