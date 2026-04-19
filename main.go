package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/wallacegibbon/proxy-config-updater/internal/clash"
)

func main() {
	var output string
	positional := parseArgs(os.Args[1:], &output)

	var allLines []string

	if len(positional) == 0 {
		// Read from stdin
		fmt.Fprintln(os.Stderr, "Reading proxy URIs from stdin...")
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fatal(fmt.Sprintf("Error reading stdin: %v", err))
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				allLines = append(allLines, line)
			}
		}
	} else {
		// Read from files
		for _, f := range positional {
			data, err := os.ReadFile(f)
			if err != nil {
				fatal(fmt.Sprintf("Error reading %s: %v", f, err))
			}
			fmt.Fprintf(os.Stderr, "Reading: %s\n", f)
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					allLines = append(allLines, line)
				}
			}
		}
	}

	// Parse proxy URIs
	var allProxies []clash.Proxy
	for _, line := range allLines {
		proxy, err := clash.ParseSingleURI(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse URI: %v\n", err)
			continue
		}
		if proxy != nil {
			allProxies = append(allProxies, *proxy)
		}
	}

	fmt.Fprintf(os.Stderr, "Total proxies: %d\n", len(allProxies))

	if len(allProxies) == 0 {
		fatal("Error: no proxies found")
	}

	// Generate config
	cfg, err := clash.GenerateConfig(allProxies)
	if err != nil {
		fatal(fmt.Sprintf("Error generating config: %v", err))
	}

	// Write output
	var writer io.Writer = os.Stdout
	if output != "" {
		file, err := os.Create(output)
		if err != nil {
			fatal(fmt.Sprintf("Error creating output file: %v", err))
		}
		defer file.Close()
		writer = file
		fmt.Fprintf(os.Stderr, "Writing: %s\n", output)
	}

	if err := clash.WriteConfig(cfg, writer); err != nil {
		fatal(fmt.Sprintf("Error writing config: %v", err))
	}

	fmt.Fprintln(os.Stderr, "Done!")
}

func parseArgs(args []string, output *string) []string {
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-output" || arg == "-o" {
			if i+1 >= len(args) {
				fatal("Error: -output requires a value")
			}
			*output = args[i+1]
			i++
		} else if len(arg) > 0 && arg[0] == '-' {
			fatal(fmt.Sprintf("Unknown flag: %s", arg))
		} else {
			positional = append(positional, arg)
		}
	}
	return positional
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
