package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
)

func (c *Client) UploadEvidence(ctx context.Context, finding, target, caption, external, name string, data []byte) (int64, error) {
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	for k, v := range map[string]string{"finding_id": finding, "target": target, "caption": caption, "external_ref": external} {
		if err := mw.WriteField(k, v); err != nil {
			return 0, err
		}
	}
	if name != "" {
		part, err := mw.CreateFormFile("file", name)
		if err != nil {
			return 0, err
		}
		if _, err = part.Write(data); err != nil {
			return 0, err
		}
	}
	if err := mw.Close(); err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.base.String()+"/api/v1/evidence", &b)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.passphrase)
	req.Header.Set("X-Cork-User", c.user)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != 201 {
		return 0, fmt.Errorf("evidence upload: %s", raw)
	}
	var result struct {
		ID int64 `json:"id"`
	}
	err = json.Unmarshal(raw, &result)
	return result.ID, err
}
