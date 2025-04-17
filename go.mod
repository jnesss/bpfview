module bpfview

go 1.24.1

replace github.com/jnesss/bpfview/types => ./types

replace github.com/jnesss/bpfview/outputformats => ./outputformats

require (
	github.com/bradleyjkemp/sigma-go v0.6.6
	github.com/cilium/ebpf v0.18.0
	github.com/fsnotify/fsnotify v1.9.0
	github.com/jnesss/bpfview/outputformats v0.0.0-00010101000000-000000000000
	github.com/jnesss/bpfview/types v0.0.0-20250410184514-307cf1204dd8
	github.com/spf13/cobra v1.9.1
)

require (
	github.com/BobuSumisu/aho-corasick v1.0.3 // indirect
	github.com/PaesslerAG/gval v1.0.0 // indirect
	github.com/PaesslerAG/jsonpath v0.1.1 // indirect
	github.com/alecthomas/participle v0.7.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-sqlite3 v1.14.27 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	golang.org/x/sys v0.30.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
