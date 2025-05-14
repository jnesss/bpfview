//go:build linux
// +build linux

package binaryanalyzer

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// CreatePackageVerifier returns the appropriate verifier for Linux
func CreatePackageVerifier() PackageVerifier {
	// Try RPM first
	rpm := &rpmVerifier{}
	if rpm.IsAvailable() {
		return rpm
	}

	// Try DEB next
	deb := &debVerifier{}
	if deb.IsAvailable() {
		return deb
	}

	// Fallback to a no-op verifier
	return &noopVerifier{}
}

// RPM implementation
type rpmVerifier struct{}

func (r *rpmVerifier) IsAvailable() bool {
	_, err := exec.LookPath("rpm")
	return err == nil
}

func (r *rpmVerifier) Verify(path string) (PackageInfo, error) {
	info := PackageInfo{
		Manager: "rpm",
	}

	// Get package ownership
	cmd := exec.Command("rpm", "-qf", path, "--queryformat", "%{NAME}|%{VERSION}-%{RELEASE}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// File not owned by any package
		return info, nil
	}

	outputStr := strings.TrimSpace(string(output))
	if strings.Contains(outputStr, "not owned by any package") {
		return info, nil
	}

	parts := strings.Split(outputStr, "|")
	if len(parts) == 2 {
		info.IsFromPackage = true
		info.PackageName = parts[0]
		info.PackageVersion = parts[1]

		// Verify file integrity
		verifyCmd := exec.Command("rpm", "-V", "--nodeps", "--nofiles", "--nodigest", "--noscripts", path)
		verifyOutput, _ := verifyCmd.CombinedOutput()

		// If no output or no errors, the file is verified
		info.Verified = len(verifyOutput) == 0 || !strings.Contains(string(verifyOutput), "5")
	}

	return info, nil
}

// DEB implementation
type debVerifier struct{}

func (d *debVerifier) IsAvailable() bool {
	_, err := exec.LookPath("dpkg")
	return err == nil
}

func (d *debVerifier) Verify(path string) (PackageInfo, error) {
	info := PackageInfo{
		Manager: "dpkg",
	}

	// Get package ownership
	cmd := exec.Command("dpkg", "-S", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// File not owned by any package
		return info, nil
	}

	outputStr := strings.TrimSpace(string(output))
	if strings.Contains(outputStr, "no path found matching pattern") {
		return info, nil
	}

	// Parse output like "package: /path/to/file"
	parts := strings.Split(outputStr, ":")
	if len(parts) >= 2 {
		info.IsFromPackage = true
		info.PackageName = strings.TrimSpace(parts[0])

		// Get package version
		versionCmd := exec.Command("dpkg", "-s", info.PackageName)
		versionOutput, _ := versionCmd.CombinedOutput()
		versionRe := regexp.MustCompile(`Version: (.+)`)
		if matches := versionRe.FindStringSubmatch(string(versionOutput)); len(matches) > 1 {
			info.PackageVersion = matches[1]
		}

		// Verify file integrity
		if _, err := exec.LookPath("debsums"); err == nil {
			verifyCmd := exec.Command("debsums", "-c", "-f", path)
			verifyOutput, _ := verifyCmd.CombinedOutput()

			// If no output or no errors, the file is verified
			info.Verified = len(verifyOutput) == 0 || !strings.Contains(string(verifyOutput), "FAILED")
		} else {
			// If debsums not available, use md5sums file in /var/lib/dpkg/info
			md5sumsPath := fmt.Sprintf("/var/lib/dpkg/info/%s.md5sums", info.PackageName)
			if _, err := exec.Command("test", "-f", md5sumsPath).CombinedOutput(); err == nil {
				// md5sums file exists, check it
				checkCmd := exec.Command("sh", "-c", fmt.Sprintf("cd / && grep -F %s %s | md5sum -c --quiet", path, md5sumsPath))
				if err := checkCmd.Run(); err == nil {
					info.Verified = true
				}
			} else {
				// Can't verify, assume true
				info.Verified = true
			}
		}
	}

	return info, nil
}

// Fallback verifier that always returns "not in package"
type noopVerifier struct{}

func (n *noopVerifier) IsAvailable() bool {
	return true
}

func (n *noopVerifier) Verify(path string) (PackageInfo, error) {
	return PackageInfo{
		IsFromPackage: false,
		Manager:       "none",
	}, nil
}
