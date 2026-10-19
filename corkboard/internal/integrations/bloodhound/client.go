package bloodhound

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	ModeTags    = "asset-group-tags"
	ModeLegacy  = "asset-groups"
	maxResponse = 4 << 20
	pageSize    = 1000
)

type Options struct {
	URL      string
	TokenID  string
	TokenKey string
}

type Info struct {
	Version string `json:"version"`
	Mode    string `json:"mode"`
}

type Result struct {
	ObjectID string `json:"object_id"`
	Name     string `json:"name"`
	Mode     string `json:"mode"`
}

type Client struct {
	base     *url.URL
	tokenID  string
	tokenKey []byte
	http     *http.Client
	now      func() time.Time
}

func New(o Options) (*Client, error) {
	u, err := url.Parse(o.URL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("bloodhound: URL must be an http(s) URL without credentials, query, or fragment")
	}
	if strings.TrimSpace(o.TokenID) == "" || strings.ContainsAny(o.TokenID, "\r\n\t ") || strings.TrimSpace(o.TokenKey) == "" {
		return nil, errors.New("bloodhound: token ID and token key are required")
	}
	return &Client{base: u, tokenID: o.TokenID, tokenKey: []byte(o.TokenKey), now: time.Now,
		http: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

type statusError struct{ code int }

func (e *statusError) Error() string { return fmt.Sprintf("bloodhound: API returned HTTP %d", e.code) }
func hasStatus(err error, code int) bool {
	var e *statusError
	return errors.As(err, &e) && e.code == code
}

func digest(key []byte, value []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(value)
	return h.Sum(nil)
}

func (c *Client) request(ctx context.Context, method, path string, body any, out any) error {
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			return errors.New("bloodhound: could not encode request")
		}
	}
	u := *c.base
	endpoint, err := url.Parse(path)
	if err != nil {
		return errors.New("bloodhound: invalid API endpoint")
	}
	u.Path = strings.TrimRight(u.Path, "/") + endpoint.Path
	u.RawPath = ""
	u.RawQuery = endpoint.RawQuery
	r, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(encoded))
	if err != nil {
		return errors.New("bloodhound: could not create request")
	}
	date := c.now().UTC().Format(time.RFC3339)
	operationKey := digest(c.tokenKey, []byte(method+r.URL.RequestURI()))
	dateKey := digest(operationKey, []byte(date[:13]))
	r.Header.Set("Authorization", "bhesignature "+c.tokenID)
	r.Header.Set("RequestDate", date)
	r.Header.Set("Signature", base64.StdEncoding.EncodeToString(digest(dateKey, encoded)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(r)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("bloodhound: request canceled: %w", ctx.Err())
		}
		return errors.New("bloodhound: connection failed or timed out")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &statusError{resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return errors.New("bloodhound: could not read API response")
	}
	if len(data) > maxResponse {
		return errors.New("bloodhound: API response exceeds size limit")
	}
	if out != nil && json.Unmarshal(data, out) != nil {
		return errors.New("bloodhound: invalid API response")
	}
	return nil
}

type group struct {
	ID   int64  `json:"id"`
	Type int    `json:"type"`
	Name string `json:"name"`
	Tag  string `json:"tag"`
}

func (c *Client) ownedGroup(ctx context.Context) (group, string, error) {
	var tags struct {
		Data struct {
			Tags []group `json:"tags"`
		} `json:"data"`
	}
	err := c.request(ctx, http.MethodGet, "/api/v2/asset-group-tags", nil, &tags)
	mode := ModeTags
	groups := tags.Data.Tags
	if hasStatus(err, http.StatusNotFound) {
		var legacy struct {
			Data struct {
				Groups []group `json:"asset_groups"`
			} `json:"data"`
		}
		err = c.request(ctx, http.MethodGet, "/api/v2/asset-groups", nil, &legacy)
		groups = legacy.Data.Groups
		mode = ModeLegacy
	}
	if err != nil {
		return group{}, "", err
	}
	var found []group
	for _, g := range groups {
		match := g.Type == 3 && strings.EqualFold(g.Name, "Owned")
		if mode == ModeLegacy {
			match = strings.EqualFold(g.Name, "Owned") && strings.EqualFold(g.Tag, "owned")
		}
		if match && g.ID > 0 {
			found = append(found, g)
		}
	}
	if len(found) != 1 {
		return group{}, "", errors.New("bloodhound: expected exactly one built-in Owned group")
	}
	return found[0], mode, nil
}

func (c *Client) RequestAnalysis(ctx context.Context) error {
	return c.request(ctx, http.MethodPut, "/api/v2/analysis", struct{}{}, nil)
}

func (c *Client) Check(ctx context.Context) (Info, error) {
	var version struct {
		Data struct {
			Version string `json:"server_version"`
		} `json:"data"`
	}
	err := c.request(ctx, http.MethodGet, "/api/version", nil, &version)
	if err != nil && !hasStatus(err, http.StatusNotFound) {
		return Info{}, err
	}
	_, mode, err := c.ownedGroup(ctx)
	if err != nil {
		return Info{}, err
	}
	if version.Data.Version == "" {
		version.Data.Version = "unknown"
	}
	return Info{Version: version.Data.Version, Mode: mode}, nil
}

type node struct {
	ObjectID string `json:"objectid"`
	Name     string `json:"name"`
	Type     string `json:"type"`
}

func (c *Client) resolve(ctx context.Context, kind, identity string) (node, error) {
	if kind != "Computer" && kind != "User" {
		return node{}, errors.New("bloodhound: kind must be Computer or User")
	}
	identity = strings.TrimSpace(identity)
	if identity == "" || strings.ContainsAny(identity, "\r\n\x00") {
		return node{}, errors.New("bloodhound: an exact object ID or qualified name is required")
	}
	matches := make(map[string]node)
	for skip := 0; skip < 100000; skip += pageSize {
		query := url.Values{"q": {identity}, "type": {kind}, "limit": {strconv.Itoa(pageSize)}, "skip": {strconv.Itoa(skip)}}
		var response struct {
			Data []node `json:"data"`
		}
		if err := c.request(ctx, http.MethodGet, "/api/v2/search?"+query.Encode(), nil, &response); err != nil {
			return node{}, err
		}
		for _, n := range response.Data {
			qualified := (kind == "Computer" && strings.Contains(identity, ".")) || (kind == "User" && strings.Contains(identity, "@"))
			if n.Type == kind && n.ObjectID != "" && n.Name != "" && (strings.EqualFold(n.ObjectID, identity) || (qualified && strings.EqualFold(n.Name, identity))) {
				matches[strings.ToUpper(n.ObjectID)] = n
			}
		}
		if len(response.Data) < pageSize {
			if len(matches) == 0 {
				return node{}, errors.New("bloodhound: no exact object match; use a qualified name or object ID")
			}
			if len(matches) != 1 {
				return node{}, errors.New("bloodhound: object identity is ambiguous; use an object ID")
			}
			for _, n := range matches {
				return n, nil
			}
		}
	}
	return node{}, errors.New("bloodhound: search result limit exceeded; use an object ID")
}

type seed struct {
	Type  int    `json:"type"`
	Value string `json:"value"`
}
type selector struct {
	Name       string  `json:"name"`
	Seeds      []seed  `json:"seeds"`
	DisabledAt *string `json:"disabled_at"`
}

func (c *Client) SyncOwned(ctx context.Context, kind, identity string) (Result, error) {
	n, err := c.resolve(ctx, kind, identity)
	if err != nil {
		return Result{}, err
	}
	g, mode, err := c.ownedGroup(ctx)
	if err != nil {
		return Result{}, err
	}
	if mode == ModeLegacy {
		body := []struct {
			Name   string `json:"selector_name"`
			SID    string `json:"sid"`
			Action string `json:"action"`
		}{{n.Name, n.ObjectID, "add"}}
		err = c.request(ctx, http.MethodPut, fmt.Sprintf("/api/v2/asset-groups/%d/selectors", g.ID), body, nil)
	} else {
		name := "corkboard:" + n.ObjectID
		path := fmt.Sprintf("/api/v2/asset-group-tags/%d/selectors", g.ID)
		var response struct {
			Data struct {
				Selectors []selector `json:"selectors"`
			} `json:"data"`
			Count int `json:"count"`
		}
		query := url.Values{"name": {"eq:" + name}, "limit": {strconv.Itoa(pageSize)}}
		err = c.request(ctx, http.MethodGet, path+"?"+query.Encode(), nil, &response)
		if err == nil {
			if response.Count > pageSize {
				return Result{}, errors.New("bloodhound: too many matching selectors")
			}
			var matching []selector
			for _, s := range response.Data.Selectors {
				if s.Name == name {
					matching = append(matching, s)
				}
			}
			if len(matching) > 1 {
				return Result{}, errors.New("bloodhound: Owned selector is ambiguous")
			}
			if len(matching) == 1 {
				s := matching[0]
				if s.DisabledAt != nil || len(s.Seeds) != 1 || s.Seeds[0].Type != 1 || !strings.EqualFold(s.Seeds[0].Value, n.ObjectID) {
					return Result{}, errors.New("bloodhound: existing Owned selector is disabled or has different seeds")
				}
			} else {
				body := struct {
					Name  string `json:"name"`
					Seeds []seed `json:"seeds"`
				}{name, []seed{{1, n.ObjectID}}}
				err = c.request(ctx, http.MethodPost, path, body, nil)
			}
		}
	}
	if err != nil {
		return Result{}, err
	}
	return Result{ObjectID: n.ObjectID, Name: n.Name, Mode: mode}, nil
}
