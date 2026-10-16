// SPDX-License-Identifier: Apache-2.0
package dashboard

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

type Asset struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	Target    string    `json:"target"`
	Owner     string    `json:"owner"`
	CreatedAt time.Time `json:"createdAt"`
}

func validateAsset(a Asset) error {
	for _, value := range []string{a.Name, a.Kind, a.Target, a.Owner} {
		if !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("fields must be single-line text")
		}
	}
	if strings.TrimSpace(a.Name) == "" || len(a.Name) > 100 || strings.TrimSpace(a.Target) == "" || len(a.Target) > 1024 || len(a.Owner) > 100 {
		return fmt.Errorf("provide a name and target within the field limits")
	}
	switch a.Kind {
	case "source", "website", "api", "backend", "application", "database", "cloud", "container", "network":
		return nil
	default:
		return fmt.Errorf("unsupported asset category")
	}
}

func loadAssets(file string) ([]Asset, error) {
	input, err := os.Open(file)
	if os.IsNotExist(err) {
		return []Asset{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer input.Close()
	data, err := io.ReadAll(io.LimitReader(input, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("inventory exceeds storage limit")
	}
	var assets []Asset
	if err := json.Unmarshal(data, &assets); err != nil {
		return nil, fmt.Errorf("invalid saved inventory: %w", err)
	}
	if len(assets) > 200 {
		return nil, fmt.Errorf("inventory exceeds 200 assets")
	}
	for _, asset := range assets {
		if err := validateAsset(asset); err != nil {
			return nil, err
		}
	}
	if assets == nil {
		assets = []Asset{}
	}
	return assets, nil
}

func saveAssets(file string, assets []Asset) error {
	data, err := json.MarshalIndent(assets, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(file), "inventory-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), file)
}
