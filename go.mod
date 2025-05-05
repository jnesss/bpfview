module bpfview

go 1.24.1

replace github.com/jnesss/bpfview/types => ./types

replace github.com/jnesss/bpfview/fingerprint => ./fingerprint

replace github.com/jnesss/bpfview/outputformats => ./outputformats

replace github.com/tursodatabase/limbo => github.com/jnesss/limbo/bindings/go v0.0.0-20250503230926-aee6259310b1

require (
	github.com/bradleyjkemp/sigma-go v0.6.6
	github.com/cilium/ebpf v0.18.0
	github.com/dgraph-io/ristretto v0.2.0
	github.com/fsnotify/fsnotify v1.9.0
	github.com/jnesss/bpfview/fingerprint v0.0.0-00010101000000-000000000000
	github.com/jnesss/bpfview/outputformats v0.0.0-00010101000000-000000000000
	github.com/jnesss/bpfview/types v0.0.0-20250425142618-5589dc619074
	github.com/prometheus/client_golang v1.22.0
	github.com/spf13/cobra v1.9.1
)

require (
	github.com/BobuSumisu/aho-corasick v1.0.3 // indirect
	github.com/PaesslerAG/gval v1.0.0 // indirect
	github.com/PaesslerAG/jsonpath v0.1.1 // indirect
	github.com/alecthomas/participle v0.7.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/ebitengine/purego v0.8.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.62.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/tursodatabase/limbo v0.0.0-00010101000000-000000000000 // indirect
	golang.org/x/sys v0.30.0 // indirect
	google.golang.org/protobuf v1.36.5 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
