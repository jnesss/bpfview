module github.com/jnesss/bpfview/outputformats

go 1.24.1

replace github.com/tursodatabase/limbo => github.com/jnesss/limbo/bindings/go v0.0.0-20250503230926-aee6259310b1

require (
	github.com/jnesss/bpfview/fingerprint v0.0.0-20250505202533-00261f99d622
	github.com/jnesss/bpfview/types v0.0.0-20250425142618-5589dc619074
	github.com/tursodatabase/limbo v0.0.0-00010101000000-000000000000
)

require (
	github.com/ebitengine/purego v0.8.2 // indirect
	golang.org/x/sys v0.29.0 // indirect
)
