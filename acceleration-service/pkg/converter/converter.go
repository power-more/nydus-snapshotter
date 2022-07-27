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

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/pkg/cri/constants"
	"github.com/containerd/containerd/snapshots"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/containerd/nydus-snapshotter/acceleration-service/pkg/config"
	"github.com/containerd/nydus-snapshotter/acceleration-service/pkg/content"
	"github.com/containerd/nydus-snapshotter/acceleration-service/pkg/driver"
	"github.com/containerd/nydus-snapshotter/acceleration-service/pkg/driver/nydus/utils"
	"github.com/containerd/nydus-snapshotter/acceleration-service/pkg/errdefs"
	"github.com/containerd/nydus-snapshotter/acceleration-service/pkg/handler"
	"github.com/containerd/nydus-snapshotter/acceleration-service/pkg/metrics"
	"github.com/containerd/nydus-snapshotter/acceleration-service/pkg/task"
)

var logger = logrus.WithField("module", "converter")

type Converter interface {
	// Dispatch dispatches a conversion task to worker queue
	// by specifying source image reference, the conversion is
	// asynchronous, and if the sync option is specified,
	// Dispatch will be blocked until the conversion is complete.
	Dispatch(ctx context.Context, ref string, manifestDigest digest.Digest, layerDigest digest.Digest, sync bool) error
	// CheckHealth checks the containerd client can successfully
	// connect to the containerd daemon and the healthcheck service
	// returns the SERVING response.
	CheckHealth(ctx context.Context) error
}

type LocalConverter struct {
	cfg         *config.Config
	rule        *Rule
	worker      *Worker
	client      *containerd.Client
	snapshotter snapshots.Snapshotter
	driver      driver.Driver
	pvd         content.Provider
}

func NewLocalConverter(cfg *config.Config, bootstrap *os.File) (*LocalConverter, error) {
	client, err := containerd.New(
		cfg.Provider.Containerd.Address,
		containerd.WithDefaultNamespace(constants.K8sContainerdNamespace),
	)
	if err != nil {
		return nil, errors.Wrap(err, "create containerd client")
	}
	logrus.Info("====zhaoshang containerdclient=====  %#+v ", *client)
	snapshotter := client.SnapshotService(cfg.Provider.Containerd.Snapshotter)

	driver, err := driver.NewLocalDriver(&cfg.Converter.Driver, bootstrap)
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

	localConverter := &LocalConverter{
		cfg:         cfg,
		rule:        rule,
		worker:      worker,
		client:      client,
		snapshotter: snapshotter,
		driver:      driver,
	}

	return localConverter, nil
}

func (cvt *LocalConverter) Convert(ctx context.Context, source string, manifestDigest digest.Digest, layerDigest digest.Digest, handler handler.Handler) error {
	ctx, done, err := cvt.client.WithLease(ctx)
	if err != nil {
		return errors.Wrap(err, "create lease")
	}
	defer done(ctx)

	target, err := cvt.rule.Map(source)
	if err != nil {
		if errors.Is(err, errdefs.ErrAlreadyConverted) {
			logrus.Infof("image has been converted: %s", source)
			return nil
		}
		return errors.Wrap(err, "create target reference by rule")
	}

	content, err := content.NewLocalProvider(
		&cvt.cfg.Provider, cvt.client, cvt.snapshotter,
	)
	if err != nil {
		return errors.Wrap(err, "create content provider")
	}

	manifest, err := utils.GetManifestbyDigest(ctx, handler.pvd.ContentStore(), manifestDigest, content.Image().Target())
	if err != nil {
		logger.Infof("pulling image %s", source)
		if err := content.Pull(ctx, source); err != nil {
			return errors.Wrap(err, "pull image")
		}
		logger.Infof("pulled image %s", source)
		manifest, err := utils.GetManifestbyDigest(ctx, content.ContentStore(), manifestDigest, content.Image().Target())
	}

	logger.Infof("converting image %s", source)
	_, err = cvt.driver.Convert(ctx, content)
	if err != nil {
		return errors.Wrap(err, "convert image")
	}
	logger.Infof("converted image %s", target)

	return nil
}

func (cvt *LocalConverter) Dispatch(ctx context.Context, ref string, manifestDigest digest.Digest, layerDigest digest.Digest, sync bool) error {
	taskID := task.Manager.Create(ref)

	if sync {
		// FIXME: The synchronous conversion task should also be
		// executed in a limited worker queue.
		return metrics.Conversion.OpWrap(func() error {
			err := cvt.Convert(ctx, ref, manifestDigest, layerDigest)
			task.Manager.Finish(taskID, err)
			return err
		}, "convert")
	}

	cvt.worker.Dispatch(func() error {
		return metrics.Conversion.OpWrap(func() error {
			err := cvt.Convert(context.Background(), ref, manifestDigest, layerDigest)
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

func (cvt *LocalConverter) GetProvider() *config.ProviderConfig {
	return &cvt.cfg.Provider
}

func (cvt *LocalConverter) GetClient() *containerd.Client {
	return cvt.client
}

func (cvt *LocalConverter) GetSnapshotter() snapshots.Snapshotter {
	return cvt.snapshotter
}
