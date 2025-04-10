module bpfview

go 1.24.1

replace github.com/jnesss/bpfview/types => ./types
replace github.com/jnesss/bpfview/outputformats => ./outputformats

require (
	github.com/cilium/ebpf v0.18.0
	github.com/jnesss/bpfview/types v0.0.0-00010101000000-000000000000
	github.com/spf13/cobra v1.9.1
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	golang.org/x/sys v0.30.0 // indirect
)
