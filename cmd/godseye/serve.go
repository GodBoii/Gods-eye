// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"godseye/internal/dashboard"
)

func serve(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "Workspace root available to source scans")
	dist := flags.String("web", "apps/web/dist", "Built frontend directory")
	state := flags.String("state", ".godseye", "Local inventory storage directory")
	port := flags.Int("port", 8765, "Loopback HTTP port")
	bind := flags.String("bind", "127.0.0.1", "Listen address: 127.0.0.1, or 0.0.0.0 inside a container")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *port < 1 || *port > 65535 || (*bind != "127.0.0.1" && *bind != "0.0.0.0") {
		fmt.Fprintln(stderr, "Invalid server arguments")
		return 2
	}
	if _, err := os.Stat(filepath.Join(*dist, "index.html")); err != nil {
		fmt.Fprintln(stderr, "Build the frontend first: npm run build in apps/web")
		return 2
	}
	app, err := dashboard.New(ctx, *root, *state)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	host := fmt.Sprintf("127.0.0.1:%d", *port)
	listener, err := net.Listen("tcp", net.JoinHostPort(*bind, fmt.Sprint(*port)))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	server := &http.Server{Handler: app.Handler(host, *dist), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			server.Shutdown(shutdown)
		case <-done:
		}
	}()
	fmt.Fprintf(stdout, "God's Eye dashboard: http://%s\nLocal access only. Inventory persists; check history lasts for this session.\n", host)
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return 0
}
