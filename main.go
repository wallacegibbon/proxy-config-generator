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
	files := args(os.Args[1:])

	// Simple flag parsing
	positional := positionalArgs(files, &output)

	if len(positional) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: proxy-config-updater [-output <path>] <url-file> [url-file2 ...]")
		fmt.Fprintln(os.Stderr, "  Each URL file contains one URL per line (proxy subscription links)")
		fmt.Fprintln(os.Stderr, "  -output string   Output file path (default: stdout)")
		os.Exit(1)
	}

	// Collect all proxy URIs from all input files
	var allLines []string
	for _, f := range positional {
		data, err := os.ReadFile(f)
		if err != nil {
			fatal(fmt.Sprintf("Error reading %s: %v", f, err))
		}
		fmt.Fprintf(os.Stderr, "Reading subscription URLs from: %s\n", f)
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				allLines = append(allLines, line)
			}
		}
	}

	// Fetch each URL and collect all proxy URIs
	var allProxies []clash.Proxy
	for i, rawURL := range allLines {
		// If it's already a proxy URI, parse directly
		if clash.IsProxyURI(rawURL) {
			proxy, err := clash.ParseSingleURI(rawURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to parse URI: %v\n", err)
				continue
			}
			if proxy != nil {
				allProxies = append(allProxies, *proxy)
			}
			continue
		}

		// It's a subscription URL — fetch it
		fmt.Fprintf(os.Stderr, "Fetching [%d/%d]: %s\n", i+1, len(allLines), rawURL)
		content, err := clash.FetchContent(rawURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: fetch failed: %v\n", err)
			continue
		}

		// Try base64 decode
		decoded, err := clash.DecodeBase64(content)
		if err != nil {
			fmt.Fprintln(os.Stderr, "  Not base64, using raw content")
			decoded = content
		}

		// Parse the content
		cfg, err := clash.ParseContent(decoded)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: parse failed: %v\n", err)
			continue
		}
		allProxies = append(allProxies, cfg.Proxies...)
	}

	fmt.Fprintf(os.Stderr, "Total proxies parsed: %d\n", len(allProxies))

	if len(allProxies) == 0 {
		fatal("Error: no proxies found from any source")
	}

	// Generate the complete config
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
		fmt.Fprintf(os.Stderr, "Writing configuration to: %s\n", output)
	}

	if err := clash.WriteConfig(cfg, writer); err != nil {
		fatal(fmt.Sprintf("Error writing config: %v", err))
	}

	fmt.Fprintln(os.Stderr, "Done!")
}

func args(osArgs []string) []string {
	return osArgs
}

func positionalArgs(allArgs []string, output *string) []string {
	var positional []string
	for i := 0; i < len(allArgs); i++ {
		arg := allArgs[i]
		if arg == "-output" {
			if i+1 >= len(allArgs) {
				fatal("Error: -output requires a value")
			}
			*output = allArgs[i+1]
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
