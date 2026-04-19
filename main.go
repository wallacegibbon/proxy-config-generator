package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/wallacegibbon/proxy-config-updater/internal/clash"
)

func main() {
	var allLines []string

	if len(os.Args) <= 1 {
		// Read from stdin
		fmt.Fprintln(os.Stderr, "Reading proxy URIs from stdin...")
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fatal(fmt.Sprintf("Error reading stdin: %v", err))
		}
		for _, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				allLines = append(allLines, line)
			}
		}
	} else {
		for _, f := range os.Args[1:] {
			data, err := os.ReadFile(f)
			if err != nil {
				fatal(fmt.Sprintf("Error reading %s: %v", f, err))
			}
			fmt.Fprintf(os.Stderr, "Reading: %s\n", f)
			for _, line := range strings.Split(string(data), "\n") {
				if line = strings.TrimSpace(line); line != "" {
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

	// Write to stdout
	if err := clash.WriteConfig(cfg, os.Stdout); err != nil {
		fatal(fmt.Sprintf("Error writing config: %v", err))
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
