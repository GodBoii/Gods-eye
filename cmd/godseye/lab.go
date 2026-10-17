// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"godseye/internal/workbench"
)

func lab(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: godseye lab catalog|import|file|pcap|iam|tcp|dns [flags] [FILE]")
		return 2
	}
	flags := flag.NewFlagSet("lab "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "", "Import format ID; see lab catalog")
	target := flags.String("target", "", "One hostname or IP for tcp; domain for dns")
	portsText := flags.String("ports", "", "1 to 32 explicit TCP ports, comma separated")
	authorized := flags.Bool("authorized", false, "Acknowledge authorization for this network target")
	output := flags.String("out", "", "Write to a new JSON file; default stdout")
	tool := flags.String("tool", "", "Tool assessment ID; see lab catalog")
	engine := flags.Bool("engine", false, "Use an explicitly supported installed engine instead of native assessment")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	var value any
	var err error
	switch args[0] {
	case "catalog":
		if flags.NArg() != 0 {
			fmt.Fprintln(stderr, "catalog accepts no file argument")
			return 2
		}
		value = map[string]any{"tools": workbench.Catalog(), "formats": workbench.Formats(), "assessments": workbench.ToolCapabilities()}
	case "assess":
		if flags.NArg() > 1 || !*authorized {
			fmt.Fprintln(stderr, "Use --tool ID --authorized, an optional --target, and at most one input file")
			return 2
		}
		request := workbench.ToolRequest{Tool: *tool, Target: *target, Authorized: *authorized, RunEngine: *engine}
		if *portsText != "" {
			for _, token := range strings.Split(*portsText, ",") {
				port, parseErr := strconv.Atoi(strings.TrimSpace(token))
				if parseErr != nil {
					fmt.Fprintln(stderr, "Use explicit comma-separated integer ports")
					return 2
				}
				request.Ports = append(request.Ports, port)
			}
		}
		if flags.NArg() == 1 {
			input, openErr := os.Open(flags.Arg(0))
			if openErr != nil {
				fmt.Fprintln(stderr, "Open assessment input failed")
				return 2
			}
			info, statErr := input.Stat()
			if statErr != nil || !info.Mode().IsRegular() {
				input.Close()
				fmt.Fprintln(stderr, "Assessment input must be a regular file")
				return 2
			}
			data, readErr := io.ReadAll(io.LimitReader(input, (workbench.MaxInput/4*3)+1))
			closeErr := input.Close()
			if readErr != nil || closeErr != nil || len(data) > workbench.MaxInput/4*3 {
				fmt.Fprintln(stderr, "Could not read assessment input within the 6 MiB limit")
				return 2
			}
			request.Input, request.Encoding = base64.StdEncoding.EncodeToString(data), "base64"
		}
		value, err = workbench.AuditTool(ctx, request)
	case "import", "file", "pcap", "iam":
		if flags.NArg() != 1 {
			fmt.Fprintln(stderr, "Provide one input file, with flags before the path")
			return 2
		}
		input, openErr := os.Open(flags.Arg(0))
		if openErr != nil {
			fmt.Fprintln(stderr, "Open input:", openErr)
			return 2
		}
		info, statErr := input.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			input.Close()
			fmt.Fprintln(stderr, "Input must be a regular file")
			return 2
		}
		data, readErr := io.ReadAll(io.LimitReader(input, workbench.MaxInput+1))
		closeErr := input.Close()
		if readErr != nil || closeErr != nil {
			fmt.Fprintln(stderr, "Read input failed")
			return 2
		}
		switch args[0] {
		case "import":
			value, err = workbench.Import(*format, data)
		case "file":
			value, err = workbench.InspectFile(data)
		case "pcap":
			value, err = workbench.InspectCapture(data)
		case "iam":
			value, err = workbench.IAM(data)
		}
	case "tcp", "dns":
		if flags.NArg() != 0 || !*authorized {
			fmt.Fprintln(stderr, "Use --target HOST and --authorized for network diagnostics")
			return 2
		}
		if args[0] == "dns" {
			value, err = workbench.DNS(ctx, *target)
		} else {
			var ports []int
			for _, token := range strings.Split(*portsText, ",") {
				port, parseErr := strconv.Atoi(strings.TrimSpace(token))
				if parseErr != nil {
					fmt.Fprintln(stderr, "Use explicit comma-separated integer ports")
					return 2
				}
				ports = append(ports, port)
			}
			value, err = workbench.TCP(ctx, *target, ports)
		}
	default:
		fmt.Fprintln(stderr, "Unknown lab command")
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "Encode report:", err)
		return 2
	}
	data = append(data, '\n')
	if *output == "" {
		if _, err := stdout.Write(data); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	} else {
		file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			fmt.Fprintln(stderr, "Create report:", err)
			return 2
		}
		_, writeErr := file.Write(data)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			fmt.Fprintln(stderr, "Report write failed; discard incomplete output")
			return 2
		}
	}
	if report, ok := value.(*workbench.Report); ok && report.Limited {
		return 3
	}
	return 0
}
