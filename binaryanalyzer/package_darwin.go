//go:build darwin
// +build darwin

package binaryanalyzer

// CreatePackageVerifier returns a stub verifier for macOS
func CreatePackageVerifier() PackageVerifier {
	return &stubVerifier{}
}

// Stub implementation for macOS to allow compilation
type stubVerifier struct{}

func (s *stubVerifier) IsAvailable() bool {
	return false
}

func (s *stubVerifier) Verify(path string) (PackageInfo, error) {
	return PackageInfo{
		IsFromPackage: false,
		Manager:       "unsupported",
	}, nil
}
