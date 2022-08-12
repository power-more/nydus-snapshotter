/*
 * Copyright (c) 2022. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package tool

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

var logger = logrus.WithField("module", "builder")

type PackOption struct {
	BuilderPath string

	BootstrapPath    string
	BlobPath         string
	FsVersion        string
	SourcePath       string
	ChunkDictPath    string
	PrefetchPatterns string
	Compressor       string
	BlobID           string
}

type MergeOption struct {
	BuilderPath string

	SourceBootstrapPaths []string
	TargetBootstrapPath  string
	ChunkDictPath        string
	PrefetchPatterns     string
}

type UnpackOption struct {
	BuilderPath   string
	BootstrapPath string
	BlobPath      string
	TarPath       string
}

func Pack(option PackOption) error {
	if option.FsVersion == "" {
		option.FsVersion = "5"
	}

	args := []string{
		"create",
		"--log-level",
		"warn",
		"--prefetch-policy",
		"fs",
		"--blob",
		option.BlobPath,
		"--blob-id",
		option.BlobID,
		"--source-type",
		"directory",
		"--whiteout-spec",
		"none",
		"--fs-version",
		option.FsVersion,
		"--inline-bootstrap",
	}
	if option.ChunkDictPath != "" {
		args = append(args, "--chunk-dict", fmt.Sprintf("bootstrap=%s", option.ChunkDictPath))
	}
	if option.PrefetchPatterns == "" {
		option.PrefetchPatterns = "/"
	}
	if option.Compressor != "" {
		args = append(args, "--compressor", option.Compressor)
	}
	args = append(args, option.SourcePath)

	logrus.Debugf("\tCommand: %s %s", option.BuilderPath, strings.Join(args[:], " "))

	cmd := exec.Command(option.BuilderPath, args...)
	cmd.Stdout = logger.Writer()
	cmd.Stderr = logger.Writer()
	cmd.Stdin = strings.NewReader(option.PrefetchPatterns)

	if err := cmd.Run(); err != nil {
		logrus.WithError(err).Errorf("fail to run %v %+v", option.BuilderPath, args)
		return err
	}

	return nil
}

func Merge(option MergeOption) error {
	args := []string{
		"merge",
		"--log-level",
		"warn",
		"--prefetch-policy",
		"fs",
		"--bootstrap",
		option.TargetBootstrapPath,
	}
	if option.ChunkDictPath != "" {
		args = append(args, "--chunk-dict", fmt.Sprintf("bootstrap=%s", option.ChunkDictPath))
	}
	if option.PrefetchPatterns == "" {
		option.PrefetchPatterns = "/"
	}
	args = append(args, option.SourceBootstrapPaths...)

	logrus.Debugf("\tCommand: %s %s", option.BuilderPath, strings.Join(args[:], " "))

	cmd := exec.Command(option.BuilderPath, args...)
	cmd.Stdout = logger.Writer()
	cmd.Stderr = logger.Writer()
	cmd.Stdin = strings.NewReader(option.PrefetchPatterns)

	if err := cmd.Run(); err != nil {
		logrus.WithError(err).Errorf("fail to run %v %+v", option.BuilderPath, args)
		return err
	}

	return nil
}

func Unpack(option UnpackOption) error {
	args := []string{
		"unpack",
		"--log-level",
		"warn",
		"--bootstrap",
		option.BootstrapPath,
		"--output",
		option.TarPath,
	}
	if option.BlobPath != "" {
		args = append(args, "--blob", option.BlobPath)
	}

	logrus.Debugf("\tCommand: %s %s", option.BuilderPath, strings.Join(args[:], " "))

	cmd := exec.Command(option.BuilderPath, args...)
	cmd.Stdout = logger.Writer()
	cmd.Stderr = logger.Writer()

	if err := cmd.Run(); err != nil {
		logrus.WithError(err).Errorf("fail to run %v %+v", option.BuilderPath, args)
		return err
	}

	return nil
}
