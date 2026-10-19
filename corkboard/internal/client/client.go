package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"corkboard/internal/ingest"
	"corkboard/internal/model"
)

const Timeout = 30 * time.Second

var (
	ErrNoServer = errors.New("no server configured (cork login or --server)")
	ErrNoCreds  = errors.New("missing --passphrase or --user (run cork login, or pass the flags)")
)

type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("server error %d (%s): %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("server error %d: %s", e.Status, e.Message)
}

func (e *APIError) ExitCode() int {
	switch {
	case e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden:
		return 3
	case e.Status >= 500:
		return 2
	default:
		return 1
	}
}

type NetworkError struct{ Err error }

func (e *NetworkError) Error() string { return "network error: " + e.Err.Error() }
func (e *NetworkError) Unwrap() error { return e.Err }
func (e *NetworkError) ExitCode() int { return 4 }

var ErrFingerprintMismatch = errors.New("TLS certificate does not match the fingerprint pinned at login (possible MITM); re-run `cork login` to re-pin deliberately")

type Client struct {
	base       *url.URL
	passphrase string
	user       string
	hc         *http.Client
	pin        []byte
	insecure   bool
}

type Options struct {
	ServerURL  string
	Passphrase string
	User       string
	Pin        string
	Insecure   bool
	Timeout    time.Duration
}

func New(o Options) (*Client, error) {
	if o.ServerURL == "" {
		return nil, ErrNoServer
	}
	u, err := url.Parse(o.ServerURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid server URL %q (want http:// or https://host:port)", o.ServerURL)
	}
	if o.Passphrase == "" || o.User == "" {
		return nil, ErrNoCreds
	}
	pin, err := hexPin(o.Pin)
	if err != nil {
		return nil, err
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = Timeout
	}
	return &Client{
		base:       u,
		passphrase: o.Passphrase,
		user:       o.User,
		pin:        pin,
		insecure:   o.Insecure,
		hc: &http.Client{
			Timeout:   timeout,
			Transport: newTransport(pin, o.Insecure, nil),
		},
	}, nil
}

func (c *Client) Server() string { return c.base.String() }

func (c *Client) User() string { return c.user }

func (c *Client) Login(ctx context.Context) (fingerprint string, who Whoami, err error) {
	host := c.base.Hostname()
	probe := &http.Client{
		Timeout: c.hc.Timeout,
		Transport: newTransport(nil, false, func(raw [][]byte, _ [][]*x509.Certificate) error {
			fp, perr := probeVerdict(host, nil, raw)
			if perr != nil {
				return perr
			}
			fingerprint = fp
			return nil
		}),
	}
	who, err = c.whoamiWith(ctx, probe)
	if err != nil {
		return "", Whoami{}, err
	}
	return fingerprint, who, nil
}

func probeVerdict(host string, roots *x509.CertPool, rawCerts [][]byte) (fingerprint string, err error) {
	if len(rawCerts) == 0 {
		return "", errors.New("server presented no certificate")
	}
	leaf, perr := x509.ParseCertificate(rawCerts[0])
	if perr != nil {
		return "", fmt.Errorf("server certificate not parseable: %w", perr)
	}
	opts := x509.VerifyOptions{DNSName: host, Roots: roots}
	if len(rawCerts) > 1 {
		pool := x509.NewCertPool()
		for _, der := range rawCerts[1:] {
			if ic, ierr := x509.ParseCertificate(der); ierr == nil {
				pool.AddCert(ic)
			}
		}
		opts.Intermediates = pool
	}
	if _, verr := leaf.Verify(opts); verr == nil {
		return "", nil
	}
	if serr := leaf.CheckSignatureFrom(leaf); serr == nil {
		sum := sha256.Sum256(rawCerts[0])
		return hex.EncodeToString(sum[:]), nil
	}
	return "", errors.New("certificate is not trusted and not self-signed: run `cork login` against the correct server, or check for a MITM")
}

func (c *Client) SetPin(pinHex string) error {
	pin, err := hexPin(pinHex)
	if err != nil {
		return err
	}
	c.pin = pin
	c.hc.Transport = newTransport(pin, c.insecure, nil)
	return nil
}

type Whoami struct {
	User       string `json:"user"`
	Version    string `json:"version"`
	Engagement string `json:"engagement"`
}

func (c *Client) whoamiWith(ctx context.Context, hc *http.Client) (Whoami, error) {
	var w Whoami
	if err := c.do(ctx, hc, http.MethodGet, "/api/v1/whoami", nil, &w); err != nil {
		return Whoami{}, err
	}
	return w, nil
}

func (c *Client) do(ctx context.Context, hc *http.Client, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, rd)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.passphrase)
	req.Header.Set("X-Cork-User", c.user)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	var resp *http.Response
	if hc == nil {
		resp, err = c.hc.Do(req)
	} else {
		resp, err = hc.Do(req)
	}
	if err != nil {
		return &NetworkError{Err: err}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return &NetworkError{Err: err}
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		msg := strings.TrimSpace(string(data))
		if json.Unmarshal(data, &e) == nil && (e.Error != "" || e.Code != "") {
			msg = e.Error
			if msg == "" {
				msg = e.Code
			}
			return &APIError{Status: resp.StatusCode, Code: e.Code, Message: msg}
		}
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		return &APIError{Status: resp.StatusCode, Message: msg}
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}
	return nil
}

func (c *Client) Whoami(ctx context.Context) (Whoami, error) {
	return c.whoamiWith(ctx, nil)
}

func (c *Client) PushBatch(ctx context.Context, b *ingest.Batch) (ingest.Result, error) {
	var res ingest.Result
	err := c.do(ctx, nil, http.MethodPost, "/api/v1/ingest/batch", b, &res)
	return res, err
}

type HostFilter struct {
	Q       string
	Tag     string
	Status  string
	Zone    string
	Owner   string
	Port    int
	Service string
	HasCred bool
	Sort    string
}

func (f HostFilter) query() url.Values {
	q := url.Values{}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	set("q", f.Q)
	set("tag", f.Tag)
	set("status", f.Status)
	set("zone", f.Zone)
	set("owner", f.Owner)
	if f.Port > 0 {
		q.Set("port", fmt.Sprintf("%d", f.Port))
	}
	set("service", f.Service)
	if f.HasCred {
		q.Set("has_cred", "1")
	}
	set("sort", f.Sort)
	return q
}

func (c *Client) ListHosts(ctx context.Context, f HostFilter) ([]model.Host, error) {
	var hosts []model.Host
	err := c.do(ctx, nil, http.MethodGet, "/api/v1/hosts?"+f.query().Encode(), nil, &hosts)
	return hosts, err
}

func (c *Client) GetHost(ctx context.Context, ip string) (*model.HostDetail, error) {
	var d model.HostDetail
	err := c.do(ctx, nil, http.MethodGet, "/api/v1/hosts/"+url.PathEscape(ip), nil, &d)
	return &d, err
}

func (c *Client) Claim(ctx context.Context, ip string, steal bool) error {
	return c.do(ctx, nil, http.MethodPost, "/api/v1/hosts/"+url.PathEscape(ip)+"/claim",
		map[string]bool{"steal": steal}, nil)
}

func (c *Client) Release(ctx context.Context, ip string) error {
	return c.do(ctx, nil, http.MethodPost, "/api/v1/hosts/"+url.PathEscape(ip)+"/release", nil, nil)
}

func (c *Client) SetStatus(ctx context.Context, ip, status, reason string) error {
	return c.do(ctx, nil, http.MethodPost, "/api/v1/hosts/"+url.PathEscape(ip)+"/status",
		map[string]string{"status": status, "reason": reason}, nil)
}

func (c *Client) AddNote(ctx context.Context, ip, body string) error {
	return c.AddLog(ctx, ip, map[string]any{"body": body})
}

func (c *Client) AddLog(ctx context.Context, ip string, entry map[string]any) error {
	return c.do(ctx, nil, http.MethodPost, "/api/v1/hosts/"+url.PathEscape(ip)+"/notes", entry, nil)
}

func (c *Client) SetTags(ctx context.Context, ip string, add, remove []string) error {
	return c.do(ctx, nil, http.MethodPost, "/api/v1/hosts/"+url.PathEscape(ip)+"/tags",
		map[string][]string{"add": add, "remove": remove}, nil)
}

func (c *Client) SetPriority(ctx context.Context, ip string, priority int) error {
	return c.do(ctx, nil, http.MethodPost, "/api/v1/hosts/"+url.PathEscape(ip)+"/priority",
		map[string]int{"priority": priority}, nil)
}

func (c *Client) SetServiceExplored(ctx context.Context, id int64, explored bool) error {
	return c.do(ctx, nil, http.MethodPost, fmt.Sprintf("/api/v1/services/%d/explored", id),
		map[string]bool{"explored": explored}, nil)
}

type TaskFilter struct {
	State    string
	Owner    string
	Priority int
	Host     string
}

func (c *Client) ListTasks(ctx context.Context, f TaskFilter) ([]model.Task, error) {
	q := url.Values{}
	if f.State != "" {
		q.Set("state", f.State)
	}
	if f.Owner != "" {
		q.Set("owner", f.Owner)
	}
	if f.Priority > 0 {
		q.Set("priority", strconv.Itoa(f.Priority))
	}
	if f.Host != "" {
		q.Set("host", f.Host)
	}
	var tasks []model.Task
	err := c.do(ctx, nil, http.MethodGet, "/api/v1/tasks?"+q.Encode(), nil, &tasks)
	return tasks, err
}

func (c *Client) CreateTask(ctx context.Context, ip string, port int, proto, title, body string, commands []string, priority int) (*model.Task, error) {
	var t model.Task
	err := c.do(ctx, nil, http.MethodPost, "/api/v1/tasks", map[string]any{
		"ip": ip, "port": port, "proto": proto, "title": title, "body": body, "commands": commands, "priority": priority,
	}, &t)
	return &t, err
}

func (c *Client) PatchTask(ctx context.Context, id int64, state, note string, steal bool) (*model.Task, error) {
	var t model.Task
	err := c.do(ctx, nil, http.MethodPatch, "/api/v1/tasks/"+strconv.FormatInt(id, 10),
		map[string]any{"state": state, "note": note, "steal": steal}, &t)
	return &t, err
}

func (c *Client) ListFindings(ctx context.Context, state string) ([]model.Finding, error) {
	q := url.Values{}
	if state != "" {
		q.Set("state", state)
	}
	var out []model.Finding
	err := c.do(ctx, nil, http.MethodGet, "/api/v1/findings?"+q.Encode(), nil, &out)
	return out, err
}

func (c *Client) PatchFinding(ctx context.Context, id int64, state, gwTitle string) error {
	return c.do(ctx, nil, http.MethodPatch, "/api/v1/findings/"+strconv.FormatInt(id, 10),
		map[string]any{"state": state, "gw_title": gwTitle}, nil)
}

func (c *Client) Targets(ctx context.Context, f HostFilter, format string) (string, error) {
	q := f.query()
	if format != "" {
		q.Set("format", format)
	}
	var out string
	err := c.doRaw(ctx, http.MethodGet, "/api/v1/targets?"+q.Encode(), &out)
	return out, err
}

type CredInput struct {
	Domain     string `json:"domain,omitempty"`
	Username   string `json:"username"`
	Secret     string `json:"secret"`
	SecretType string `json:"secret_type"`
	Notes      string `json:"notes,omitempty"`
	Access     []struct {
		IP       string `json:"ip"`
		Protocol string `json:"protocol"`
		Level    string `json:"level"`
	} `json:"access,omitempty"`
}

func (c *Client) ListCreds(ctx context.Context) ([]model.Cred, error) {
	var out []model.Cred
	err := c.do(ctx, nil, http.MethodGet, "/api/v1/creds", nil, &out)
	return out, err
}

func (c *Client) AddCred(ctx context.Context, in CredInput) (int64, error) {
	var out struct {
		CredID int64 `json:"cred_id"`
	}
	if err := c.do(ctx, nil, http.MethodPost, "/api/v1/creds", in, &out); err != nil {
		return 0, err
	}
	return out.CredID, nil
}

func (c *Client) AddCredAccess(ctx context.Context, id int64, ip, protocol, level string) error {
	body := map[string]string{"ip": ip, "protocol": protocol, "level": level}
	return c.do(ctx, nil, http.MethodPost, fmt.Sprintf("/api/v1/creds/%d/access", id), body, nil)
}

func (c *Client) RevealCred(ctx context.Context, id int64) (string, error) {
	var out struct {
		CredID int64  `json:"cred_id"`
		Secret string `json:"secret"`
	}
	if err := c.do(ctx, nil, http.MethodGet, fmt.Sprintf("/api/v1/creds/%d/reveal", id), nil, &out); err != nil {
		return "", err
	}
	return out.Secret, nil
}

func (c *Client) doRaw(ctx context.Context, method, path string, out *string) error {
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, nil)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.passphrase)
	req.Header.Set("X-Cork-User", c.user)
	resp, err := c.hc.Do(req)
	if err != nil {
		return &NetworkError{Err: err}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return &NetworkError{Err: err}
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		msg := strings.TrimSpace(string(data))
		if json.Unmarshal(data, &e) == nil && (e.Error != "" || e.Code != "") {
			msg = e.Error
			if msg == "" {
				msg = e.Code
			}
			return &APIError{Status: resp.StatusCode, Code: e.Code, Message: msg}
		}
		return &APIError{Status: resp.StatusCode, Message: msg}
	}
	*out = string(data)
	return nil
}

type SetOwnedInput struct {
	Level        string `json:"level"`
	ViaFindingID *int64 `json:"via_finding_id,omitempty"`
	ViaCredID    *int64 `json:"via_cred_id,omitempty"`
	ViaText      string `json:"via_text,omitempty"`
}

func (c *Client) SetOwned(ctx context.Context, ip string, in SetOwnedInput) error {
	return c.do(ctx, nil, http.MethodPost, "/api/v1/hosts/"+url.PathEscape(ip)+"/owned", in, nil)
}

func (c *Client) Purge(ctx context.Context, confirm string) (map[string]any, error) {
	var out map[string]any
	err := c.do(ctx, nil, http.MethodPost, "/api/v1/admin/purge",
		map[string]string{"confirm": confirm}, &out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) Export(ctx context.Context, kind string, reveal bool) (string, error) {
	path := "/api/v1/export/" + kind
	if reveal {
		path += "?reveal=1"
	}
	var out string
	err := c.doRaw(ctx, http.MethodGet, path, &out)
	return out, err
}

func newTransport(pin []byte, insecure bool, verify func(rawCerts [][]byte, chains [][]*x509.Certificate) error) *http.Transport {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case insecure:
		tlsCfg.InsecureSkipVerify = true
	case verify != nil:

		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			return verify(rawCerts, chains)
		}
	case len(pin) > 0:

		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("server presented no certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
				return ErrFingerprintMismatch
			}
			return nil
		}
	}
	return &http.Transport{TLSClientConfig: tlsCfg}
}

func hexPin(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "sha256:")
	if s == "" {
		return nil, nil
	}
	b, err := hexDecode(s)
	if err != nil {
		return nil, fmt.Errorf("invalid tls_fingerprint %q: %v", s, err)
	}
	if len(b) != sha256.Size {
		return nil, fmt.Errorf("invalid tls_fingerprint: want 32 bytes, got %d", len(b))
	}
	return b, nil
}

func hexDecode(s string) ([]byte, error) {
	var out []byte
	for i := 0; i < len(s); i += 2 {
		if i+2 > len(s) {
			return nil, errors.New("odd length")
		}
		hi, ok1 := hexVal(s[i])
		lo, ok2 := hexVal(s[i+1])
		if !ok1 || !ok2 {
			return nil, errors.New("non-hex character")
		}
		out = append(out, hi<<4|lo)
	}
	return out, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func (c *Client) UploadScreenshot(ctx context.Context, name string, data []byte) (sha string, existed bool, err error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, ferr := mw.CreateFormFile("file", name)
	if ferr != nil {
		return "", false, ferr
	}
	if _, err := io.Copy(fw, bytes.NewReader(data)); err != nil {
		return "", false, err
	}
	if err := mw.Close(); err != nil {
		return "", false, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.base.String()+"/api/v1/screenshots", &buf)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.passphrase)
	req.Header.Set("X-Cork-User", c.user)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", false, &NetworkError{Err: err}
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, &NetworkError{Err: err}
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		if json.Unmarshal(data2, &e) == nil && e.Error != "" {
			return "", false, &APIError{Status: resp.StatusCode, Code: e.Code, Message: e.Error}
		}
		return "", false, &APIError{Status: resp.StatusCode, Message: strings.TrimSpace(string(data2))}
	}
	var res struct {
		SHA256    string `json:"sha256"`
		Duplicate bool   `json:"duplicate"`
	}
	if err := json.Unmarshal(data2, &res); err != nil {
		return "", false, fmt.Errorf("decoding response: %w", err)
	}
	return res.SHA256, res.Duplicate, nil
}
