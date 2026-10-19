package client

import (
	"context"
	"fmt"
	"net/http"
)

func (c *Client) Workflow(ctx context.Context, method, path string, in, out any) error {
	return c.do(ctx, nil, method, path, in, out)
}
func (c *Client) RecordFinding(ctx context.Context, in any) (int64, error) {
	var result struct {
		ID int64 `json:"id"`
	}
	err := c.do(ctx, nil, http.MethodPost, "/api/v1/findings", in, &result)
	return result.ID, err
}
func (c *Client) FindingDetail(ctx context.Context, id int64, out any) error {
	return c.do(ctx, nil, http.MethodGet, fmt.Sprintf("/api/v1/findings/%d", id), nil, out)
}
