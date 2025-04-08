package main

import (
    "github.com/spf13/cobra"
)

func setupCLI() *cobra.Command {
    var config FilterConfig

    rootCmd := &cobra.Command{
        Use:   "bpfview",
        Short: "Process and network monitoring tool",
    }

    // Process flags
    rootCmd.Flags().StringSliceVar(&config.CommandNames, "comm", nil, "Filter by command names")
    rootCmd.Flags().StringSliceVar(&config.CmdlineContains, "cmdline", nil, "Filter by command line patterns")
    rootCmd.Flags().BoolVar(&config.TrackTree, "tree", false, "Track process tree")
    
    // Network flags
    rootCmd.Flags().StringSliceVar(&config.SrcPorts, "sport", nil, "Source ports")
    rootCmd.Flags().StringSliceVar(&config.DstPorts, "dport", nil, "Destination ports")
    
    // Output flags
    rootCmd.Flags().StringVar(&config.OutputFormat, "output", "text", "Output format (text/json)")
    rootCmd.Flags().StringVar(&config.OutputFile, "file", "", "Output file")

    return rootCmd
}
