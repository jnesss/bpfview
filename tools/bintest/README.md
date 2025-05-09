# Binary Analyzer Test Harness

This tool provides a standalone interface to test the BinaryAnalyzer package functionality.

## Usage

```
go run main.go -binary /path/to/binary [-db /path/to/db.db] [-v]
```

Options:
- `-binary`: Path to binary file to analyze (required)
- `-db`: Path to SQLite database for storing binary metadata (default: ./binarymetadata.db)
- `-v`: Verbose output mode

## Examples

Analyze a system binary:
```go run main.go -binary /bin/bash -v```

Analyze a custom binary with custom database location:
```go run main.go -binary ./myapp -db ./metadata.db```
