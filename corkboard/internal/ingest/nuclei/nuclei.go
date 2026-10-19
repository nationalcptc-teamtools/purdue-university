package nuclei

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"corkboard/internal/ingest"
)

type result struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string   `json:"name"`
		Severity       string   `json:"severity"`
		Description    string   `json:"description"`
		Reference      []string `json:"reference"`
		Classification struct {
			CVEID []string `json:"cve-id"`
		} `json:"classification"`
	} `json:"info"`
	Host             string   `json:"host"`
	IP               string   `json:"ip"`
	Port             int      `json:"port"`
	MatchedAt        string   `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
	Timestamp        string   `json:"timestamp"`
}

func Parse(r io.Reader) (*ingest.Batch, error) {
	b := &ingest.Batch{Version: ingest.BatchVersion}
	b.Run.Kind = "nuclei"
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		if raw[0] == '[' {
			return ParseArray(raw)
		}
		var res result
		if err := json.Unmarshal(raw, &res); err != nil {
			b.Warnings = append(b.Warnings, fmt.Sprintf("line %d: not nuclei JSON, skipped", line))
			continue
		}
		if v := convert(res); v != nil {
			b.Vulns = append(b.Vulns, *v)
		} else {
			b.Warnings = append(b.Warnings, fmt.Sprintf("line %d: no template-id, skipped", line))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("nuclei: %w", err)
	}
	return b, nil
}

func ParseArray(data []byte) (*ingest.Batch, error) {
	var raws []json.RawMessage
	if err := json.Unmarshal(data, &raws); err != nil {
		return nil, fmt.Errorf("nuclei: not a JSON array: %w", err)
	}
	b := &ingest.Batch{Version: ingest.BatchVersion}
	b.Run.Kind = "nuclei"
	for i, raw := range raws {
		var res result
		if err := json.Unmarshal(raw, &res); err != nil {
			b.Warnings = append(b.Warnings, fmt.Sprintf("element %d: not nuclei JSON, skipped", i))
			continue
		}
		if v := convert(res); v != nil {
			b.Vulns = append(b.Vulns, *v)
		}
	}
	return b, nil
}

func convert(res result) *ingest.VulnObs {
	if strings.TrimSpace(res.TemplateID) == "" {
		return nil
	}
	v := &ingest.VulnObs{
		TemplateID:  strings.TrimSpace(res.TemplateID),
		Name:        strings.TrimSpace(res.Info.Name),
		Severity:    strings.ToLower(strings.TrimSpace(res.Info.Severity)),
		Description: strings.TrimSpace(res.Info.Description),
		References:  res.Info.Reference,
		IP:          strings.TrimSpace(res.IP),
		Port:        res.Port,
		MatchedAt:   strings.TrimSpace(res.MatchedAt),
	}
	if v.Severity == "unknown" {
		v.Severity = "info"
	}
	if v.Name == "" {
		v.Name = v.TemplateID
	}
	if len(res.Info.Classification.CVEID) > 0 {
		v.CVE = strings.Join(res.Info.Classification.CVEID, ",")
	}
	if len(res.ExtractedResults) > 0 {
		v.Extracted = res.ExtractedResults[0]
	}
	if v.MatchedAt == "" {
		v.MatchedAt = strings.TrimSpace(res.Host)
	}
	return v
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
	return bytes.Contains(line, []byte(`"template-id"`))
}
