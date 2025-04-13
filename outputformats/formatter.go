package outputformats

import "github.com/jnesss/bpfview/types"

// EventFormatter defines the interface for different output formats
type EventFormatter interface {
	Initialize() error
	Close() error

	FormatProcess(event *types.ProcessEvent, info *types.ProcessInfo) error
	FormatNetwork(event *types.NetworkEvent, info *types.ProcessInfo) error
	FormatDNS(event *types.UserSpaceDNSEvent, info *types.ProcessInfo) error
	FormatTLS(event *types.UserSpaceTLSEvent, info *types.ProcessInfo) error
	FormatSigmaMatch(match *types.SigmaMatch) error
}
