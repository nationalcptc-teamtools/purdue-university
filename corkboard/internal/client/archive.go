package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"corkboard/internal/archive"
)

func (c *Client) ExportArchive(ctx context.Context, dst io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.String()+"/api/v1/archive/export", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.passphrase)
	req.Header.Set("X-Cork-User", c.user)
	hc := *c.hc
	hc.Timeout = 30 * time.Minute
	resp, err := hc.Do(req)
	if err != nil {
		return &NetworkError{Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &APIError{Status: resp.StatusCode, Message: strings.TrimSpace(string(b))}
	}
	if resp.ContentLength > archive.MaxBytes {
		return fmt.Errorf("archive exceeds 32 GiB limit")
	}
	n, err := io.Copy(dst, io.LimitReader(resp.Body, archive.MaxBytes+1))
	if err != nil {
		return err
	}
	if n > archive.MaxBytes {
		return fmt.Errorf("archive exceeds 32 GiB limit")
	}
	return nil
}
