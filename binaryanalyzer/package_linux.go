//go:build linux
// +build linux

package binaryanalyzer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
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
	// Check if RPM database directory exists
	_, err := os.Stat("/var/lib/rpm")
	return err == nil
}

func (r *rpmVerifier) Verify(path string) (PackageInfo, error) {
	info := PackageInfo{
		Manager: "rpm",
	}

	// We still need exec.Command for RPM, but we'll make it safe as possible
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Execute rpm command with separate arguments (no shell expansion)
	cmd := exec.CommandContext(ctx, "rpm", "-qf", path, "--queryformat", "%{NAME}|%{VERSION}-%{RELEASE}")
	output, err := cmd.CombinedOutput()

	// Check for timeout or other errors
	if ctx.Err() == context.DeadlineExceeded {
		return info, fmt.Errorf("rpm command timed out: %w", ctx.Err())
	}

	outputStr := strings.TrimSpace(string(output))
	if err != nil || strings.Contains(outputStr, "not owned by any package") {
		return info, ErrPackageNotFound
	}

	parts := strings.Split(outputStr, "|")
	if len(parts) == 2 {
		info.IsFromPackage = true
		info.PackageName = parts[0]
		info.PackageVersion = parts[1]

		// Verify file integrity more safely
		verifyCtx, verifyCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer verifyCancel()

		// Use specific verification arguments to check only this file
		verifyCmd := exec.CommandContext(verifyCtx, "rpm", "-V", "--nodeps", "--nofiles", "--nodigest", "--noscripts", path)
		verifyOutput, verifyErr := verifyCmd.CombinedOutput()

		// If no output or no errors, the file is verified
		if verifyCtx.Err() == context.DeadlineExceeded {
			// Handle timeout by marking as unverified rather than erroring
			info.Verified = false
		} else if verifyErr != nil || strings.Contains(string(verifyOutput), "5") {
			info.Verified = false
		} else {
			info.Verified = true
		}
	}

	return info, nil
}

// DEB implementation with direct file parsing
type debVerifier struct{}

func (d *debVerifier) IsAvailable() bool {
	// Check if dpkg database directory exists
	_, err := os.Stat("/var/lib/dpkg")
	return err == nil
}

func (d *debVerifier) Verify(path string) (PackageInfo, error) {
	info := PackageInfo{
		Manager: "dpkg",
	}

	// 1. Find which package owns this file by parsing dpkg database
	packageforfile, err := d.findPackageForFile(path)
	if err != nil {
		return info, err
	}

	if packageforfile == "" {
		return info, ErrPackageNotFound
	}

	info.IsFromPackage = true
	info.PackageName = packageforfile

	// 2. Get package version by parsing status file
	version, err := d.getPackageVersion(packageforfile)
	if err != nil {
		return info, err
	}
	info.PackageVersion = version

	// 3. Verify file integrity by checking MD5 sum
	verified, err := d.verifyFileIntegrity(path, packageforfile)
	if err != nil {
		// Don't fail on verification error, just mark as unverified
		info.Verified = false
	} else {
		info.Verified = verified
	}

	return info, nil
}

// findPackageForFile searches dpkg database to find which package owns a file
func (d *debVerifier) findPackageForFile(path string) (string, error) {
	// We cannot easily parse the dpkg database without exec.Command
	// But we can make it safer by using context and proper argument separation
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dpkg", "-S", path)
	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("dpkg command timed out: %w", ctx.Err())
	}

	if err != nil {
		return "", ErrPackageNotFound
	}

	outputStr := strings.TrimSpace(string(output))
	if strings.Contains(outputStr, "no path found matching pattern") {
		return "", ErrPackageNotFound
	}

	// Parse output like "package: /path/to/file"
	parts := strings.Split(outputStr, ":")
	if len(parts) >= 2 {
		return strings.TrimSpace(parts[0]), nil
	}

	return "", ErrPackageNotFound
}

// getPackageVersion gets the installed version of a package
func (d *debVerifier) getPackageVersion(packageName string) (string, error) {
	// Parse /var/lib/dpkg/status file directly
	statusFile, err := os.Open("/var/lib/dpkg/status")
	if err != nil {
		return "", err
	}
	defer statusFile.Close()

	scanner := bufio.NewScanner(statusFile)
	inPackage := false
	var version string

	for scanner.Scan() {
		line := scanner.Text()

		// If we find a new package entry
		if strings.HasPrefix(line, "Package: ") {
			packageField := strings.TrimPrefix(line, "Package: ")
			inPackage = (packageField == packageName)
		}

		// If we're in the correct package section and find the version
		if inPackage && strings.HasPrefix(line, "Version: ") {
			version = strings.TrimPrefix(line, "Version: ")
			break
		}
	}

	if version == "" {
		return "", fmt.Errorf("package version not found: %w", ErrPackageNotFound)
	}

	return version, nil
}

// verifyFileIntegrity checks if a file matches its expected MD5 sum
func (d *debVerifier) verifyFileIntegrity(path string, packageName string) (bool, error) {
	// First try with debsums if available
	if d.isDebsumsAvailable() {
		return d.verifyWithDebsums(path, packageName)
	}

	// Otherwise use MD5SUMS file directly
	return d.verifyWithMd5sums(path, packageName)
}

// isDebsumsAvailable checks if debsums is installed
func (d *debVerifier) isDebsumsAvailable() bool {
	_, err := os.Stat("/usr/bin/debsums")
	return err == nil
}

// verifyWithDebsums uses debsums to verify file integrity
func (d *debVerifier) verifyWithDebsums(path string, packageName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "debsums", "-c", "-f", path)
	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return false, fmt.Errorf("debsums command timed out: %w", ctx.Err())
	}

	// If no error and no "FAILED" in output, file is verified
	if err == nil && !strings.Contains(string(output), "FAILED") {
		return true, nil
	}

	return false, nil
}

// verifyWithMd5sums parses MD5SUMS file manually to verify file integrity
func (d *debVerifier) verifyWithMd5sums(path string, packageName string) (bool, error) {
	// Calculate the absolute file path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}

	// Transform to relative path from root
	relPath := strings.TrimPrefix(absPath, "/")

	// Find potential MD5SUMS files
	md5sumsPath := fmt.Sprintf("/var/lib/dpkg/info/%s.md5sums", packageName)

	// Check if file exists
	_, err = os.Stat(md5sumsPath)
	if err != nil {
		return false, fmt.Errorf("md5sums file not found: %w", err)
	}

	// Read MD5SUMS file
	md5File, err := os.Open(md5sumsPath)
	if err != nil {
		return false, err
	}
	defer md5File.Close()

	// Parse MD5SUMS to find expected hash
	scanner := bufio.NewScanner(md5File)
	var expectedMD5 string

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) == 2 {
			filePath := parts[1]
			if filePath == relPath {
				expectedMD5 = parts[0]
				break
			}
		}
	}

	if expectedMD5 == "" {
		// File not found in MD5SUMS
		return false, fmt.Errorf("file not found in md5sums: %w", ErrVerifyFailed)
	}

	// Calculate actual MD5
	actualMD5, err := calculateMD5(path)
	if err != nil {
		return false, err
	}

	// Compare hashes
	return (expectedMD5 == actualMD5), nil
}

// calculateMD5 calculates the MD5 hash of a file
func calculateMD5(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
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
