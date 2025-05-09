package binaryanalyzer

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
)

// Cache of hash calculations to avoid recalculating
var (
	hashCacheMutex sync.RWMutex
	md5Cache       = make(map[string]string)
	sha256Cache    = make(map[string]string)
)

// CalculateMD5 computes the MD5 hash of a file
func CalculateMD5(path string) (string, error) {
	// Check cache first
	hashCacheMutex.RLock()
	cachedHash, exists := md5Cache[path]
	hashCacheMutex.RUnlock()
	
	if exists {
		return cachedHash, nil
	}
	
	// Open the file
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	// Create hasher
	hasher := md5.New()
	
	// Copy file content to hasher
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	
	// Get the hash
	hashBytes := hasher.Sum(nil)
	hashString := hex.EncodeToString(hashBytes)
	
	// Store in cache
	hashCacheMutex.Lock()
	md5Cache[path] = hashString
	hashCacheMutex.Unlock()
	
	return hashString, nil
}

// CalculateSHA256 computes the SHA256 hash of a file
func CalculateSHA256(path string) (string, error) {
	// Check cache first
	hashCacheMutex.RLock()
	cachedHash, exists := sha256Cache[path]
	hashCacheMutex.RUnlock()
	
	if exists {
		return cachedHash, nil
	}
	
	// Open the file
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	// Create hasher
	hasher := sha256.New()
	
	// Copy file content to hasher
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	
	// Get the hash
	hashBytes := hasher.Sum(nil)
	hashString := hex.EncodeToString(hashBytes)
	
	// Store in cache
	hashCacheMutex.Lock()
	sha256Cache[path] = hashString
	hashCacheMutex.Unlock()
	
	return hashString, nil
}
