package client

import (
	"context"
	"net/http"
)

type BloodHoundTarget struct {
	ID           int64  `json:"id"`
	Kind         string `json:"kind"`
	Identity     string `json:"identity"`
	IP           string `json:"ip,omitempty"`
	State        string `json:"state"`
	HostID       *int64 `json:"host_id,omitempty"`
	ObjectID     string `json:"object_id,omitempty"`
	ResolvedName string `json:"resolved_name,omitempty"`
	UpdatedAt    int64  `json:"updated_at"`
	SyncedAt     int64  `json:"synced_at"`
	Error        string `json:"error,omitempty"`
	LastError    string `json:"last_error,omitempty"`
}

type BloodHoundStatus struct {
	Enabled    bool               `json:"enabled"`
	AutoSync   bool               `json:"auto_sync"`
	URL        string             `json:"url"`
	Configured bool               `json:"configured"`
	Error      string             `json:"error,omitempty"`
	Targets    []BloodHoundTarget `json:"targets"`
	Version    string             `json:"version,omitempty"`
	Mode       string             `json:"mode,omitempty"`
	LastError  string             `json:"last_error,omitempty"`
	LastSyncAt int64              `json:"last_sync_at,omitempty"`
}

type BloodHoundCheck struct {
	Version string `json:"version"`
	Mode    string `json:"mode"`
}

type BloodHoundTargetInput struct {
	Kind     string `json:"kind"`
	Identity string `json:"identity"`
	IP       string `json:"ip,omitempty"`
}

func (c *Client) BloodHoundStatus(ctx context.Context) (BloodHoundStatus, error) {
	var out BloodHoundStatus
	err := c.do(ctx, nil, http.MethodGet, "/api/v1/bloodhound/status", nil, &out)
	return out, err
}

func (c *Client) BloodHoundCheck(ctx context.Context) (BloodHoundCheck, error) {
	var out BloodHoundCheck
	err := c.do(ctx, nil, http.MethodPost, "/api/v1/bloodhound/check", struct{}{}, &out)
	return out, err
}

func (c *Client) BloodHoundOwned(ctx context.Context, input BloodHoundTargetInput) (BloodHoundTarget, error) {
	var out BloodHoundTarget
	err := c.do(ctx, nil, http.MethodPost, "/api/v1/bloodhound/targets", input, &out)
	return out, err
}

func (c *Client) BloodHoundSync(ctx context.Context) (bool, error) {
	var out struct {
		Queued bool `json:"queued"`
	}
	err := c.do(ctx, nil, http.MethodPost, "/api/v1/bloodhound/sync", struct{}{}, &out)
	return out.Queued, err
}
