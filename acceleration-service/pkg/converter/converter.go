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
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/containerd/containerd"
	containerdcontent "github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/pkg/cri/constants"
	"github.com/containerd/containerd/snapshots"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/containerd/nydus-snapshotter/acceleration-service/pkg/config"
	"github.com/containerd/nydus-snapshotter/acceleration-service/pkg/content"
	"github.com/containerd/nydus-snapshotter/acceleration-service/pkg/driver"
	"github.com/containerd/nydus-snapshotter/acceleration-service/pkg/driver/nydus/utils"
	"github.com/containerd/nydus-snapshotter/acceleration-service/pkg/metrics"
	"github.com/containerd/nydus-snapshotter/acceleration-service/pkg/task"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var logger = logrus.WithField("module", "converter")

type Converter interface {
	// Dispatch dispatches a conversion task to worker queue
	// by specifying source image reference, the conversion is
	// asynchronous, and if the sync option is specified,
	// Dispatch will be blocked until the conversion is complete.
	Dispatch(ctx context.Context, ref string, manifestDigest digest.Digest, layerDigest digest.Digest, blob *os.File, sync bool, isLastLayer bool, key string) error

	Merge(ctx context.Context, blobs []string, bootstrap *os.File) error
	// CheckHealth checks the containerd client can successfully
	// connect to the containerd daemon and the healthcheck service
	// returns the SERVING response.
	CheckHealth(ctx context.Context) error

	GetWaitGroupMap() map[digest.Digest]*errgroup.Group
}

type LocalConverter struct {
	cfg         *config.Config
	rule        *Rule
	worker      *Worker
	client      *containerd.Client
	snapshotter snapshots.Snapshotter
	driver      driver.Driver
	pvd         content.Provider
	// key is manifest digest, value is layers' descriptors (manifest.Layers)
	manifestLayersMap    map[digest.Digest][]ocispec.Descriptor
	manifestWaitGroupMap map[digest.Digest]*errgroup.Group
}

func NewLocalConverter(cfg *config.Config) (*LocalConverter, error) {
	client, err := containerd.New(
		cfg.Provider.Containerd.Address,
		containerd.WithDefaultNamespace(constants.K8sContainerdNamespace),
	)
	if err != nil {
		return nil, errors.Wrap(err, "create containerd client")
	}
	logrus.Infof("====zhaoshang containerdclient=====  %#+v ", *client)
	snapshotter := client.SnapshotService(cfg.Provider.Containerd.Snapshotter)

	driver, err := driver.NewLocalDriver(&cfg.Converter.Driver)
	if err != nil {
		return nil, errors.Wrap(err, "create driver")
	}

	worker, err := NewWorker(cfg.Converter.Worker)
	if err != nil {
		return nil, errors.Wrap(err, "create worker")
	}

	rule := &Rule{
		items: cfg.Converter.Rules,
	}

	pvd, err := content.NewLocalProvider(
		&cfg.Provider, client, snapshotter,
	)
	if err != nil {
		return nil, errors.Wrap(err, "create content provider")
	}

	localConverter := &LocalConverter{
		cfg:                  cfg,
		rule:                 rule,
		worker:               worker,
		client:               client,
		snapshotter:          snapshotter,
		driver:               driver,
		pvd:                  pvd,
		manifestLayersMap:    make(map[digest.Digest][]ocispec.Descriptor),
		manifestWaitGroupMap: make(map[digest.Digest]*errgroup.Group),
	}

	return localConverter, nil
}

func (cvt *LocalConverter) Merge(ctx context.Context, blobs []string, bootstrap *os.File) error {
	return cvt.driver.Merge(ctx, cvt.pvd, blobs, bootstrap)
}

func (cvt *LocalConverter) Convert(ctx context.Context, source string, manifestDigest digest.Digest, currentLayerDigest digest.Digest, blob *os.File, isLastLayer bool, key string) error {
	ctx, done, err := cvt.client.WithLease(ctx)
	if err != nil {
		return errors.Wrap(err, "create lease")
	}
	defer done(ctx)

	// check content if current layer exist
	cs := cvt.pvd.ContentStore()
	if _, err = cs.Info(ctx, currentLayerDigest); err != nil {
		// if ErrNotFound, pull image
		if !strings.Contains(err.Error(), errdefs.ErrNotFound.Error()) {
			return errors.Wrap(err, "get info of layer")
		}
		logger.Infof("pulling image %s", source)
		start := time.Now()
		if err := cvt.pvd.Pull(ctx, source); err != nil {
			return errors.Wrap(err, "pull image")
		}
		logger.Infof("pulled image %s, elapse %s", source, time.Since(start))
	}

	descs, ok := cvt.manifestLayersMap[manifestDigest]
	if !ok {
		cs = cvt.pvd.ContentStore()
		manifest, err := utils.GetManifestbyDigest(ctx, cs, manifestDigest, cvt.pvd.Image().Target())
		if err != nil {
			return err
		}
		descs, err = utils.GetLayersbyManifestDescriptor(ctx, cs, *manifest)
		if err != nil {
			return err
		}
		cvt.manifestLayersMap[manifestDigest] = descs
	}

	logrus.Infof("====zhaoshang cvt.manifestLayersMap %+v", cvt.manifestLayersMap)
	for _, layerDesc := range descs {
		if layerDesc.Digest != currentLayerDigest {
			continue
		}

		if cvt.cfg.Converter.Async {
			// go convertThread
			logrus.Infof("====zhaoshang wait map %#v", cvt.manifestWaitGroupMap[manifestDigest])
			cvt.manifestWaitGroupMap[manifestDigest].Go(cvt.convertThread(ctx, cvt.pvd, layerDesc, blob))
		} else {
			logger.Infof("converting layer %s in image %s", currentLayerDigest, source)
			start := time.Now()
			if _, err := cvt.driver.Convert(ctx, cvt.pvd, layerDesc, blob); err != nil {
				return errors.Wrap(err, "converting layer")
			}
			logger.Infof("converted layer %s in image %s, elapse %s", currentLayerDigest, source, time.Since(start))
		}
		break
	}

	if cvt.cfg.Converter.Async && isLastLayer {
		// wait group
		logrus.Infof("====zhaoshang wait start, %#v", cvt.manifestWaitGroupMap[manifestDigest])
		if err := cvt.manifestWaitGroupMap[manifestDigest].Wait(); err != nil { // group 的wait方法，等待上面的 g.go的协程执行完成，并且可以接受错误
			logrus.Infof("====zhaoshang wait err %#v", err)
			return errors.Wrap(err, "converting layer async")
		}
		logrus.Infof("====zhaoshang wait success")
	}

	return nil
}

func (cvt *LocalConverter) convertThread(ctx context.Context, provider content.Provider, layerDesc ocispec.Descriptor, blob *os.File) func() error {
	return func() error {
		if _, err := cvt.driver.Convert(ctx, cvt.pvd, layerDesc, blob); err != nil {
			return errors.Wrap(err, "converting layer")
		}
		return nil
	}
}

func (cvt *LocalConverter) Dispatch(ctx context.Context, ref string, manifestDigest digest.Digest, layerDigest digest.Digest, blob *os.File, sync bool, isLastLayer bool, key string) error {
	taskID := task.Manager.Create(ref)

	if sync {
		// FIXME: The synchronous conversion task should also be
		// executed in a limited worker queue.
		return metrics.Conversion.OpWrap(func() error {
			err := cvt.Convert(ctx, ref, manifestDigest, layerDigest, blob, isLastLayer, key)
			task.Manager.Finish(taskID, err)
			return err
		}, "convert")
	}

	cvt.worker.Dispatch(func() error {
		return metrics.Conversion.OpWrap(func() error {
			err := cvt.Convert(context.Background(), ref, manifestDigest, layerDigest, blob, isLastLayer, key)
			task.Manager.Finish(taskID, err)
			return err
		}, "convert")
	})

	return nil
}

func (cvt *LocalConverter) CheckHealth(ctx context.Context) error {
	health, err := cvt.client.IsServing(ctx)

	msg := "containerd service is unhealthy"
	if err != nil {
		return errors.Wrap(err, msg)
	}

	if !health {
		return fmt.Errorf(msg)
	}

	return nil
}

func (cvt *LocalConverter) GetContentStore() containerdcontent.Store {
	return cvt.pvd.ContentStore()
}

func (cvt *LocalConverter) GetWaitGroupMap() map[digest.Digest]*errgroup.Group {
	return cvt.manifestWaitGroupMap
}
