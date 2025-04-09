package main

import (
    "crypto/md5"
    "encoding/hex"
    "io"
    "os"
    "sync"
)

// BinaryHashCache caches MD5 hashes of files to avoid
// recalculating the same hash multiple times
var (
    binaryHashCache     = make(map[string]string)
    binaryHashCacheLock sync.RWMutex
)

// CalculateMD5 computes the MD5 hash of a file
func CalculateMD5(filePath string) (string, error) {
    // Check cache first
    binaryHashCacheLock.RLock()
    hash, exists := binaryHashCache[filePath]
    binaryHashCacheLock.RUnlock()
    
    if exists {
        return hash, nil
    }
    
    // Open the file
    file, err := os.Open(filePath)
    if err != nil {
        return "", err
    }
    defer file.Close()
    
    // Create MD5 hasher
    hasher := md5.New()
    
    // Copy file content to hasher
    _, err = io.Copy(hasher, file)
    if err != nil {
        return "", err
    }
    
    // Get hash and convert to hex string
    hashBytes := hasher.Sum(nil)
    hashString := hex.EncodeToString(hashBytes)
    
    // Store in cache
    binaryHashCacheLock.Lock()
    binaryHashCache[filePath] = hashString
    binaryHashCacheLock.Unlock()
    
    return hashString, nil
}
