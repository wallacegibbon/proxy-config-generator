package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/wallacegibbon/proxy-config-updater/internal/clash"
	"gopkg.in/yaml.v3"
)

func main() {
	var output string
	pretty := true
	urlFile := ""

	// Manual flag parsing to allow flags anywhere in the argument list.
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if len(arg) > 0 && arg[0] == '-' {
			switch arg {
			case "-output":
				if i+1 >= len(args) {
					fatal("Error: -output requires a value")
				}
				output = args[i+1]
				i++
			case "-pretty":
				pretty = true
			case "-pretty=false":
				pretty = false
			default:
				fatal(fmt.Sprintf("Unknown flag: %s", arg))
			}
		} else if urlFile == "" {
			urlFile = arg
		} else {
			fatal(fmt.Sprintf("Error: unexpected argument: %s", arg))
		}
	}

	if urlFile == "" {
		fmt.Fprintln(os.Stderr, "Usage: proxy-config-updater <url-file> [options]")
		fmt.Fprintln(os.Stderr, "  -output string   Output file path (default: stdout)")
		fmt.Fprintln(os.Stderr, "  -pretty          Pretty print output (default true)")
		os.Exit(1)
	}

	// Read subscription URL from file
	subscriptionURL := readURLFile(urlFile)
	fmt.Fprintf(os.Stderr, "Reading URL from file: %s\n", urlFile)

	// Fetch full proxy list with generic User-Agent
	fmt.Fprintf(os.Stderr, "Fetching subscription from: %s\n", subscriptionURL)
	encodedContent, err := clash.FetchContent(subscriptionURL)
	if err != nil {
		fatal(fmt.Sprintf("Error fetching content: %v", err))
	}

	// Fetch Clash YAML format for proxy-groups and rules
	fmt.Fprintln(os.Stderr, "Fetching Clash format for proxy-groups and rules...")
	clashCfg := clash.FetchClashConfig(subscriptionURL)

	// Decode content (try base64, fall back to raw)
	fmt.Fprintln(os.Stderr, "Decoding base64 content...")
	decodedContent, err := clash.DecodeBase64(encodedContent)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Warning: Content is not base64 encoded, trying raw content...")
		decodedContent = encodedContent
	}

	// Parse the configuration
	fmt.Fprintln(os.Stderr, "Parsing configuration...")
	cfg, err := clash.ParseContent(decodedContent)
	if err != nil {
		fatal(fmt.Sprintf("Error parsing config: %v", err))
	}

	// Merge proxy-groups and rules from the Clash YAML response
	if clashCfg != nil {
		clash.MergeClash(cfg, clashCfg)
	}

	fmt.Fprintf(os.Stderr, "Configuration loaded: %d proxies, %d groups, %d rules\n",
		len(cfg.Proxies), len(cfg.ProxyGroups), len(cfg.Rules))

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

	if pretty {
		defaultCfg, _ := clash.LoadDefaultConfig()
		if defaultCfg == nil {
			defaultCfg = &clash.ClashConfig{}
		}
		merged := clash.MergeConfigs(defaultCfg, cfg)
		yamlData, err := yaml.Marshal(merged)
		if err != nil {
			fatal(fmt.Sprintf("Error marshaling YAML: %v", err))
		}
		writer.Write(yamlData)
	} else {
		writer.Write([]byte(decodedContent))
	}

	fmt.Fprintln(os.Stderr, "\nDone!")
}

// readURLFile reads and trims a subscription URL from a file.
func readURLFile(filename string) string {
	data, err := os.ReadFile(filename)
	if err != nil {
		fatal(fmt.Sprintf("Error reading URL file: %v", err))
	}
	url := strings.TrimSpace(string(data))
	if url == "" {
		fatal("Error: URL file is empty")
	}
	return url
}

// fatal prints a message to stderr and exits.
func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
