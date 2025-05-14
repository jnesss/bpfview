package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jnesss/bpfview/binaryanalyzer"
	_ "github.com/tursodatabase/limbo"
)

// Simple logger that implements the Logger interface
type simpleLogger struct {
	verbose bool
}

func (l *simpleLogger) Debug(component, format string, args ...interface{}) {
	if l.verbose {
		fmt.Printf("[DEBUG][%s] %s\n", component, fmt.Sprintf(format, args...))
	}
}

func (l *simpleLogger) Info(component, format string, args ...interface{}) {
	fmt.Printf("[INFO][%s] %s\n", component, fmt.Sprintf(format, args...))
}

func (l *simpleLogger) Warning(component, format string, args ...interface{}) {
	fmt.Printf("[WARNING][%s] %s\n", component, fmt.Sprintf(format, args...))
}

func (l *simpleLogger) Error(component, format string, args ...interface{}) {
	fmt.Printf("[ERROR][%s] %s\n", component, fmt.Sprintf(format, args...))
}

func main() {
	// Command line flags
	binary := flag.String("binary", "", "Binary to analyze")
	dbPath := flag.String("db", "./binarymetadata.db", "Path to binary metadata database")
	verbose := flag.Bool("v", false, "Verbose output")

	flag.Parse()

	if *binary == "" {
		fmt.Println("Please specify a binary with -binary flag")
		flag.Usage()
		os.Exit(1)
	}

	// Create analyzer
	analyzer, err := binaryanalyzer.New(binaryanalyzer.Config{
		DBPath:  *dbPath,
		Workers: 1,
		Logger:  &simpleLogger{verbose: *verbose},
	})
	if err != nil {
		fmt.Printf("Error initializing analyzer: %v\n", err)
		os.Exit(1)
	}
	defer analyzer.Close()

	// Submit binary for analysis
	analyzer.SubmitBinary(*binary)

	// Wait a moment for analysis to complete
	time.Sleep(500 * time.Millisecond)

	// Get metadata
	metadata, found := analyzer.GetMetadataByPath(*binary)
	if !found {
		fmt.Println("Binary analysis failed or binary not found")
		os.Exit(1)
	}

	// Print analysis results
	fmt.Println("=== Binary Analysis Results ===")
	fmt.Printf("File:        %s\n", metadata.Path)
	fmt.Printf("Size:        %d bytes\n", metadata.FileSize)
	fmt.Printf("Modified:    %s\n", metadata.ModTime.Format(time.RFC3339))
	fmt.Printf("First Seen:  %s\n", metadata.FirstSeen.Format(time.RFC3339))
	fmt.Printf("MD5 Hash:    %s\n", metadata.MD5Hash)
	fmt.Printf("SHA256 Hash: %s\n", metadata.SHA256Hash)

	// Display package information
	fmt.Println("\n=== Package Information ===")
	if metadata.IsFromPackage {
		fmt.Printf("Package:       %s\n", metadata.PackageName)
		fmt.Printf("Version:       %s\n", metadata.PackageVersion)
		fmt.Printf("Manager:       %s\n", metadata.PackageManager)
		fmt.Printf("From Package:  %v\n", metadata.IsFromPackage)
		fmt.Printf("Verified:      %v\n", metadata.PackageVerified)
	} else {
		fmt.Println("This binary is not part of any system package")
	}

	// Display ELF information if available
	if metadata.IsELF {
		fmt.Println("\n=== ELF Analysis ===")
		fmt.Printf("Type:              %s\n", metadata.ELFType)
		fmt.Printf("Architecture:      %s\n", metadata.Architecture)
		fmt.Printf("Interpreter:       %s\n", metadata.Interpreter)
		fmt.Printf("Statically Linked: %v\n", metadata.IsStaticallyLinked)
		fmt.Printf("Debug Info:        %v\n", metadata.HasDebugInfo)

		fmt.Printf("\nImported Libraries: %d\n", len(metadata.ImportedLibraries))
		for i, lib := range metadata.ImportedLibraries {
			if i < 10 || *verbose { // Show all with verbose, otherwise just first 10
				fmt.Printf("  - %s\n", lib)
			} else if i == 10 {
				fmt.Printf("  - ... (%d more)\n", len(metadata.ImportedLibraries)-10)
				break
			}
		}

		// Change this section to show counts:
		fmt.Printf("\nImported Symbols: %d\n", metadata.ImportedSymbolCount)
		fmt.Printf("Exported Symbols: %d\n", metadata.ExportedSymbolCount)

		// In the future we'll display actual symbol data for key binaries
		// and implement similarity detection to find binary variants

		if *verbose {
			fmt.Printf("\nSections: %d\n", len(metadata.Sections))
			for _, section := range metadata.Sections {
				fmt.Printf("  - %s\n", section)
			}
		}
	} else {
		fmt.Println("\nNot an ELF binary or ELF analysis not available")
	}
}
