package binaryanalyzer

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

// CreatePackageVerifier returns the appropriate verifier for the system
// This function is implemented in platform-specific files
// func CreatePackageVerifier() PackageVerifier
