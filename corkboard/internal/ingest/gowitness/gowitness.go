package gowitness

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"corkboard/internal/ingest"
)

type result struct {
	URL          string   `json:"url"`
	FinalURL     string   `json:"final_url"`
	ResponseCode int      `json:"response_code"`
	Title        string   `json:"title"`
	Failed       bool     `json:"failed"`
	FailedReason string   `json:"failed_reason"`
	ProbedAt     probedAt `json:"probed_at"`
	FileName     string   `json:"file_name"`
	Technologies []struct {
		Value string `json:"value"`
	} `json:"technologies"`
	TLS struct {
		SubjectName string `json:"subject_name"`
		SANList     []struct {
			Value string `json:"value"`
		} `json:"san_list"`
	} `json:"tls"`
}

type probedAt int64

func (p *probedAt) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s == "" {
			*p = 0
			return nil
		}
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return err
		}
		*p = probedAt(t.UnixMilli())
		return nil
	}
	var sec int64
	if err := json.Unmarshal(data, &sec); err != nil {
		return err
	}
	*p = probedAt(sec * 1000)
	return nil
}

func Parse(r io.Reader) (*ingest.Batch, error) {
	b := &ingest.Batch{Version: ingest.BatchVersion}
	b.Run.Kind = "gowitness"
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	seen := map[string]int{}
	line := 0
	for sc.Scan() {
		line++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}

		if raw[0] == '[' {
			return parseArray(raw)
		}
		var res result
		if err := json.Unmarshal(raw, &res); err != nil {
			b.Warnings = append(b.Warnings, fmt.Sprintf("line %d: not gowitness JSON, skipped", line))
			continue
		}
		w := convert(res)
		if w.URL == "" {
			b.Warnings = append(b.Warnings, fmt.Sprintf("line %d: no url, skipped", line))
			continue
		}
		if i, dup := seen[w.URL]; dup {

			b.WebResults[i] = w
		} else {
			seen[w.URL] = len(b.WebResults)
			b.WebResults = append(b.WebResults, w)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("gowitness: %w", err)
	}
	return b, nil
}

func ParseArray(data []byte) (*ingest.Batch, error) {
	var raws []json.RawMessage
	if err := json.Unmarshal(data, &raws); err != nil {
		return nil, fmt.Errorf("gowitness: not a JSON array: %w", err)
	}
	b := &ingest.Batch{Version: ingest.BatchVersion}
	b.Run.Kind = "gowitness"
	for i, raw := range raws {
		var res result
		if err := json.Unmarshal(raw, &res); err != nil {
			b.Warnings = append(b.Warnings, fmt.Sprintf("element %d: not gowitness JSON, skipped", i))
			continue
		}
		w := convert(res)
		if w.URL == "" {
			b.Warnings = append(b.Warnings, fmt.Sprintf("element %d: no url, skipped", i))
			continue
		}
		b.WebResults = append(b.WebResults, w)
	}
	return b, nil
}

func parseArray(raw []byte) (*ingest.Batch, error) {
	return ParseArray(raw)
}

func convert(res result) ingest.WebObs {
	w := ingest.WebObs{
		URL:          strings.TrimSpace(res.URL),
		FinalURL:     res.FinalURL,
		StatusCode:   res.ResponseCode,
		Title:        strings.TrimSpace(res.Title),
		Failed:       res.Failed,
		FailedReason: res.FailedReason,
		ProbedAt:     int64(res.ProbedAt),
	}
	for _, t := range res.Technologies {
		if t.Value != "" {
			w.Technologies = append(w.Technologies, t.Value)
		}
	}
	if res.TLS.SubjectName != "" {
		w.TLSSubject = res.TLS.SubjectName
	}
	for _, san := range res.TLS.SANList {
		if san.Value != "" {
			w.TLSSANs = append(w.TLSSANs, san.Value)
		}
	}
	w.ScreenshotSHA = res.FileName
	return w
}

func Detect(data []byte) bool {
	trimmed := bytes.TrimLeft(data, " \t\r\n\xef\xbb\xbf")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}
	line := trimmed
	if i := bytes.IndexByte(trimmed, '\n'); i >= 0 {
		line = trimmed[:i]
	}
	return bytes.Contains(line, []byte(`"url"`)) && bytes.Contains(line, []byte(`"probed_at"`))
}

func ScreenshotKey(ref string) string {
	if u, err := url.Parse(ref); err == nil && u.Path != "" {
		ref = u.Path
	}
	if i := strings.LastIndexByte(ref, '/'); i >= 0 {
		ref = ref[i+1:]
	}
	return strings.TrimSpace(ref)
}

func ParseStatusCode(s string) (int, error) { return strconv.Atoi(s) }
