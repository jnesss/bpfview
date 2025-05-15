package binaryanalyzer

import (
	"errors"
)

// Package verification errors
var (
	ErrPackageNotFound    = errors.New("binary not found in any package")
	ErrVerifyFailed       = errors.New("package verification failed")
	ErrSystemNotSupported = errors.New("package system not supported")
)

// PackageVerifier provides package verification functionality
type PackageVerifier interface {
	// Verify checks if a binary belongs to a package and returns package info
	Verify(path string) (PackageInfo, error)
	// IsAvailable checks if this package manager is available on the system
	IsAvailable() bool
}

// PackageInfo contains package verification results
type PackageInfo struct {
	IsFromPackage  bool
	PackageName    string
	PackageVersion string
	Verified       bool
	Manager        string // "rpm", "dpkg", etc.
}
