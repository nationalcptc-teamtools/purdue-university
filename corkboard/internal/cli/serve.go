package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"corkboard/internal/config"
	"corkboard/internal/db"
	"corkboard/internal/scope"
	"corkboard/internal/server"
	"corkboard/internal/store"
)

var Version = "dev"

func RunServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	dataDir := fs.String("data", "cork-data", "data directory (contains server.yaml and scope.yaml)")
	listen := fs.String("listen", "", "override listen address from server.yaml")
	engage := fs.String("engagement", "", "override engagement name from server.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v (usage: cork serve [--data DIR] [--listen ADDR] [--engagement NAME])", fs.Args())
	}
	abs, err := filepath.Abs(*dataDir)
	if err != nil {
		return err
	}

	cfg, err := config.LoadServer(filepath.Join(abs, "server.yaml"))
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%v (run `cork init --data %s` first)", err, abs)
	} else if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *engage != "" {
		cfg.EngagementName = *engage
	}
	d, err := db.Open(filepath.Join(abs, "cork.db"))
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer d.Close()

	scData, err := os.ReadFile(filepath.Join(abs, "scope.yaml"))
	if err != nil {
		return fmt.Errorf("reading scope.yaml: %v (run `cork init --data %s` first)", err, abs)
	}
	sc, err := scope.Load(scData)
	if err != nil {
		return fmt.Errorf("scope.yaml: %w", err)
	}

	srv := server.New(cfg, store.New(d), sc, abs, Version)
	return srv.Run()
}
