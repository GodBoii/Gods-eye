// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	pb "godseye/gen/go/godseye/v1"
	"godseye/internal/report"
	"godseye/internal/secrets"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "lab" {
		return lab(ctx, args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "serve" {
		return serve(ctx, args[1:], stdout, stderr)
	}
	if len(args) == 1 && args[0] == "version" {
		fmt.Fprintln(stdout, "godseye 0.4.0")
		return 0
	}
	if len(args) == 0 || args[0] != "scan" {
		fmt.Fprintln(stderr, "Usage: godseye scan [--format json|sarif] [--out FILE] [--project ID] [--timeout 30s] DIRECTORY\n       godseye lab catalog|assess|import|file|pcap|iam|tcp|dns [flags] [FILE]\n       godseye serve [flags]\n       godseye version")
		return 2
	}
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "json", "Report format: json or sarif")
	output := flags.String("out", "", "New report file; default stdout. Existing files are never overwritten.")
	project := flags.String("project", "local", "Project identity used in fingerprints")
	timeout := flags.Duration("timeout", 30*time.Second, "Maximum scan duration")
	limits := secrets.DefaultLimits()
	flags.IntVar(&limits.Workers, "workers", limits.Workers, "Parallel file workers, 1-32")
	flags.IntVar(&limits.MaxFiles, "max-files", limits.MaxFiles, "Maximum file entries inspected")
	flags.Int64Var(&limits.MaxFileBytes, "max-file-bytes", limits.MaxFileBytes, "Maximum bytes per text file, up to 16 MiB")
	flags.Int64Var(&limits.MaxTotalBytes, "max-total-bytes", limits.MaxTotalBytes, "Maximum input read budget")
	flags.IntVar(&limits.MaxFindings, "max-findings", limits.MaxFindings, "Maximum retained findings, up to 10000")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if flags.NArg() != 1 || (*format != "json" && *format != "sarif") || *timeout <= 0 {
		fmt.Fprintln(stderr, "Provide one directory, a supported format, and a positive timeout. Flags precede the directory.")
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	result, err := secrets.Scan(ctx, flags.Arg(0), *project, limits)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	var data []byte
	if *format == "json" {
		data, err = report.JSON(result)
	} else {
		data, err = report.SARIF(result)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	data = append(data, '\n')
	if *output == "" {
		if _, err = stdout.Write(data); err != nil {
			fmt.Fprintln(stderr, "write report:", err)
			return 2
		}
	} else {
		f, openErr := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if openErr != nil {
			fmt.Fprintln(stderr, "create report:", openErr)
			return 2
		}
		_, writeErr := f.Write(data)
		syncErr := f.Sync()
		closeErr := f.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			fmt.Fprintln(stderr, "Report write failed; discard incomplete output.", writeErr, syncErr, closeErr)
			return 2
		}
	}
	fmt.Fprintf(stderr, "%s: %d files scanned, %d findings, %d exclusions\n", result.Summary.Status, result.FilesScanned, len(result.Findings), result.Excluded)
	if result.Summary.Status != pb.RunStatus_RUN_STATUS_SUCCEEDED {
		return 3
	}
	if len(result.Findings) > 0 {
		return 1
	}
	return 0
}
