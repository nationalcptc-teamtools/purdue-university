package nmap

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"

	"corkboard/internal/coverage"
	"corkboard/internal/ingest"
)

func Parse(r io.Reader) (*ingest.Batch, error) {
	dec := xml.NewDecoder(r)
	b := &ingest.Batch{Version: 1}
	b.Run.Kind = "nmap"
	b.Run.Fidelity = 1
	b.Run.Exit = "unknown"
	sawRun := false
	sawClose := false
	byIP := map[string]int{}
	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				if !sawClose {
					return nil, fmt.Errorf("nmap: truncated XML (missing closing </nmaprun>)")
				}
				break
			}
			if !sawRun {
				return nil, fmt.Errorf("nmap: %w", err)
			}
			return nil, fmt.Errorf("nmap: malformed XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "nmaprun":
				sawRun = true
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "args":
						b.Run.Command = a.Value
					case "start":
						if n, err := strconv.ParseInt(a.Value, 10, 64); err == nil {
							b.Run.StartedAt = n * 1000
						}
					case "scanner":
						if a.Value == "masscan" {
							b.Run.Kind = "masscan"
						}
					}
				}
			case "scaninfo":
				si := ingest.ScanInfo{}
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "protocol":
						si.Protocol = a.Value
					case "services":
						si.Services = a.Value
					case "numservices":
						si.NumServices, _ = strconv.Atoi(a.Value)
					}
				}
				b.Run.ScanInfo = append(b.Run.ScanInfo, si)
			case "host":
				h, ok, err := decodeHost(dec, t, b.Run.Kind == "masscan")
				if err != nil {
					return nil, err
				}
				if ok {
					if i, seen := byIP[h.IP]; seen {
						mergeHost(&b.Hosts[i], h)
					} else {
						byIP[h.IP] = len(b.Hosts)
						b.Hosts = append(b.Hosts, h)
					}
				}
			case "runstats":
				if err := readRunStats(dec, &b.Run); err != nil {
					return nil, err
				}
			}
		case xml.EndElement:
			if t.Name.Local == "nmaprun" {
				sawClose = true
			}
		}
	}

	if stages := coverage.UniformStages(b.Run); len(stages) > 0 {
		for _, h := range b.Hosts {
			for _, stage := range stages {
				if coverage.HostStageStatus(b.Run, h, stage) == "completed" {
					b.Coverage = append(b.Coverage, ingest.CoverageObs{IP: h.IP, Stage: stage})
				}
			}
		}
	}
	if !sawRun {
		return nil, fmt.Errorf("nmap: missing <nmaprun> root element")
	}
	return b, nil
}

func readRunStats(dec *xml.Decoder, run *ingest.RunInfo) error {
	var rs struct {
		Finished struct {
			Time  string `xml:"time,attr"`
			Exit  string `xml:"exit,attr"`
			Error string `xml:"errormsg,attr"`
		} `xml:"finished"`
	}
	if err := dec.DecodeElement(&rs, &xml.StartElement{Name: xml.Name{Local: "runstats"}}); err != nil {
		return err
	}
	if n, err := strconv.ParseInt(rs.Finished.Time, 10, 64); err == nil {
		run.FinishedAt = n * 1000
	}
	if rs.Finished.Exit != "" {
		run.Exit = rs.Finished.Exit
	}
	run.Error = rs.Finished.Error
	return nil
}

type hostXML struct {
	End      int64    `xml:"endtime,attr"`
	TimedOut bool     `xml:"timedout,attr"`
	XMLName  xml.Name `xml:"host"`
	Status   struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
		Vendor   string `xml:"vendor,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	} `xml:"hostnames>hostname"`
	Ports []struct {
		PortID   int    `xml:"portid,attr"`
		Protocol string `xml:"protocol,attr"`
		State    struct {
			State  string `xml:"state,attr"`
			Reason string `xml:"reason,attr"`
		} `xml:"state"`
		Service struct {
			Method     string   `xml:"method,attr"`
			Confidence int      `xml:"conf,attr"`
			OS         string   `xml:"ostype,attr"`
			Name       string   `xml:"name,attr"`
			Product    string   `xml:"product,attr"`
			Version    string   `xml:"version,attr"`
			ExtraInfo  string   `xml:"extrainfo,attr"`
			Tunnel     string   `xml:"tunnel,attr"`
			CPE        []string `xml:"cpe"`
		} `xml:"service"`
		Scripts []scriptXML `xml:"script"`
	} `xml:"ports>port"`
	Extra []struct {
		State   string `xml:"state,attr"`
		Count   int    `xml:"count,attr"`
		Reasons []struct {
			Proto string `xml:"proto,attr"`
			Ports string `xml:"ports,attr"`
			Count int    `xml:"count,attr"`
		} `xml:"extrareasons"`
	} `xml:"ports>extraports"`
	OS []struct {
		Name     string `xml:"name,attr"`
		Accuracy string `xml:"accuracy,attr"`
		Classes  []struct {
			Family string `xml:"osfamily,attr"`
		} `xml:"osclass"`
	} `xml:"os>osmatch"`
	HostScripts []scriptXML `xml:"hostscript>script"`
}

type scriptXML struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
	Inner  string `xml:",innerxml"`
}

func (s scriptXML) output() string {
	if strings.TrimSpace(s.Output) != "" {
		return ingest.TruncateScriptOutput(s.Output)
	}
	d := xml.NewDecoder(strings.NewReader("<root>" + s.Inner + "</root>"))
	var b bytes.Buffer
	for b.Len() <= ingest.ScriptOutputLimit {
		t, err := d.Token()
		if err != nil {
			break
		}
		switch v := t.(type) {
		case xml.StartElement:
			for _, a := range v.Attr {
				if a.Name.Local == "key" {
					b.WriteString(a.Value + ": ")
				}
			}
		case xml.CharData:
			b.Write(bytes.TrimSpace(v))
		case xml.EndElement:
			if v.Name.Local != "root" {
				b.WriteByte('\n')
			}
		}
	}
	return ingest.TruncateScriptOutput(strings.TrimSpace(b.String()))
}

type identity struct {
	names map[string]bool
}

func decodeHost(dec *xml.Decoder, se xml.StartElement, noStatus bool) (ingest.HostObs, bool, error) {
	var hx hostXML
	if err := dec.DecodeElement(&hx, &se); err != nil {
		return ingest.HostObs{}, false, fmt.Errorf("nmap: <host>: %w", err)
	}
	h := ingest.HostObs{Attrs: map[string]string{}}
	if !noStatus {
		h.Scan = &ingest.ScanEvidence{Reason: hx.Status.Reason, TimedOut: hx.TimedOut, At: hx.End * 1000}
		h.Scan.Responded = hx.Status.State == "up" && hx.Status.Reason != "user-set" && hx.Status.Reason != "no-response" && hx.Status.Reason != ""
	}

	ip := ""
	for _, a := range hx.Addresses {
		switch a.AddrType {
		case "ipv4", "ipv6":
			if ip == "" {
				ip = a.Addr
			}
		case "mac":
			h.MAC = a.Addr
			h.MACVendor = a.Vendor
		}
	}
	if ip == "" {
		return ingest.HostObs{}, false, nil
	}
	h.IP = ip
	for _, ex := range hx.Extra {
		if h.Scan == nil {
			break
		}
		e := ingest.ExtraPorts{State: ex.State, Count: ex.Count}
		if len(ex.Reasons) == 1 {
			e.Proto = ex.Reasons[0].Proto
			e.Ports = ex.Reasons[0].Ports
		}
		h.Scan.Extra = append(h.Scan.Extra, e)
		if ex.State == "closed" && ex.Count > 0 {
			h.Scan.Responded = true
		}
	}

	for _, n := range hx.Hostnames {
		src := "nmap"
		switch n.Type {
		case "PTR":
			src = "nmap-ptr"
		case "user":
			src = "nmap-user"
		}
		h.Hostnames = append(h.Hostnames, ingest.NameObs{Name: n.Name, Source: src})
	}

	for _, p := range hx.Ports {
		st := p.State.State
		if h.Scan != nil {
			h.Scan.Ports = append(h.Scan.Ports, ingest.PortState{Proto: p.Protocol, Port: p.PortID, State: st, Reason: p.State.Reason})
			if st == "open" || st == "closed" {
				h.Scan.Responded = true
			}
		}
		if st != "open" && st != "open|filtered" {
			continue
		}
		svc := ingest.ServiceObs{
			Method: p.Service.Method, Confidence: p.Service.Confidence, OSHint: p.Service.OS,
			Proto:     p.Protocol,
			Port:      p.PortID,
			State:     st,
			Name:      p.Service.Name,
			Product:   p.Service.Product,
			Version:   p.Service.Version,
			ExtraInfo: p.Service.ExtraInfo,
			Tunnel:    p.Service.Tunnel,
			CPE:       p.Service.CPE,
		}
		for _, s := range p.Scripts {
			svc.Scripts = append(svc.Scripts, ingest.ScriptObs{
				ID:     s.ID,
				Output: s.output(),
			})
		}
		h.Services = append(h.Services, svc)
	}

	for _, s := range hx.HostScripts {
		h.HostScripts = append(h.HostScripts, ingest.ScriptObs{
			ID:     s.ID,
			Output: s.output(),
		})
	}

	best := -1
	for _, o := range hx.OS {
		if acc, _ := strconv.Atoi(o.Accuracy); acc > best {
			best = acc
		}
	}
	for _, o := range hx.OS {
		acc, _ := strconv.Atoi(o.Accuracy)
		family := ingest.OSFamily(o.Name)
		if len(o.Classes) > 0 {
			family = strings.ToLower(o.Classes[0].Family)
		}
		h.OSEvidence = append(h.OSEvidence, ingest.OSEvidence{Name: o.Name, Family: family, Source: "nmap-os", Accuracy: acc, At: hx.End * 1000})
		if best > 0 && acc == best && h.OS == "" {
			h.OS = o.Name
			h.OSAcc = acc
		}
	}

	ident := &identity{names: map[string]bool{}}
	for _, n := range h.Hostnames {
		ident.names[n.Name] = true
	}
	extractIdentity(&h, hx.HostScripts, ident)
	for _, p := range hx.Ports {
		extractIdentity(&h, p.Scripts, ident)
		if p.Service.OS != "" {
			h.OSEvidence = append(h.OSEvidence, ingest.OSEvidence{Name: p.Service.OS, Family: ingest.OSFamily(p.Service.OS), Source: "service-hint", At: hx.End * 1000})
		}
	}
	return h, true, nil
}

func mergeHost(dst *ingest.HostObs, src ingest.HostObs) {
	for _, s := range src.Services {
		dup := false
		for _, e := range dst.Services {
			if e.Proto == s.Proto && e.Port == s.Port {
				dup = true
				break
			}
		}
		if !dup {
			dst.Services = append(dst.Services, s)
		}
	}
	dst.HostScripts = append(dst.HostScripts, src.HostScripts...)
	for _, n := range src.Hostnames {
		dup := false
		for _, e := range dst.Hostnames {
			if e.Name == n.Name {
				dup = true
				break
			}
		}
		if !dup {
			dst.Hostnames = append(dst.Hostnames, n)
		}
	}
	for k, v := range src.Attrs {
		dst.Attrs[k] = v
	}
	if src.MAC != "" {
		dst.MAC, dst.MACVendor = src.MAC, src.MACVendor
	}
	if src.OS != "" {
		dst.OS, dst.OSAcc = src.OS, src.OSAcc
	}
	if src.Domain != "" {
		dst.Domain = src.Domain
	}
}

func extractIdentity(h *ingest.HostObs, scripts []scriptXML, ident *identity) {
	for _, s := range scripts {
		s.Output = s.output()
		switch s.ID {
		case "ssl-cert":
			for _, name := range parseSSLCert(s.Output) {
				addName(h, name, "tls-cert", ident)
			}
		case "rdp-ntlm-info":
			kv := parseColonFields(s.Output)
			if build := kv["Product_Version"]; build != "" {
				h.OSEvidence = append(h.OSEvidence, ingest.OSEvidence{Name: "Windows (RDP reported build " + build + ")", Family: "windows", Build: build, Source: "rdp-ntlm-info"})
			}
			for _, key := range []string{"DNS_Computer_Name", "FQDN"} {
				if v := kv[key]; v != "" {
					addName(h, v, "rdp-ntlm-info", ident)
				}
			}
			setDomain(h, kv["NetBIOS_Domain_Name"], kv["DNS_Domain_Name"])
		case "smb-os-discovery":
			kv := parseColonFields(s.Output)
			if os := kv["OS"]; os != "" && !strings.EqualFold(os, "unknown") {
				h.OSEvidence = append(h.OSEvidence, ingest.OSEvidence{Name: os, Family: ingest.OSFamily(os), Source: "smb-os-discovery"})
			}
			for _, key := range []string{"FQDN", "NetBIOS_Computer_Name", "Computer name", "NetBIOS computer name"} {
				if v := kv[key]; v != "" {
					addName(h, v, "smb-os-discovery", ident)
				}
			}
			setDomain(h, kv["NetBIOS_Domain_Name"], kv["DNS_Domain_Name"])
			setDomain(h, kv["Domain name"], kv["NetBIOS domain name"])
		case "smb2-security-mode":
			switch {
			case strings.Contains(s.Output, "not required"):
				h.Attrs["smb_signing"] = "false"
			case strings.Contains(s.Output, "required"):
				h.Attrs["smb_signing"] = "true"
			}
		case "smb-security-mode":
			if strings.Contains(s.Output, "message_signing: disabled") {
				h.Attrs["smb_signing"] = "false"
			}
			if strings.Contains(s.Output, "SMB1") {
				h.Attrs["smbv1"] = "true"
			}
		case "rdp-enum-encryption":
			if strings.Contains(s.Output, "CredSSP (NLA): SUCCESS") {
				h.Attrs["rdp_nla"] = "true"
			}
		}
	}
}

func parseSSLCert(output string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if subj, ok := strings.CutPrefix(line, "Subject:"); ok {
			subj = strings.TrimSpace(subj)
			if i := strings.Index(subj, "commonName="); i >= 0 {
				rest := subj[i+len("commonName="):]
				if j := strings.IndexAny(rest, ",\n"); j >= 0 {
					rest = rest[:j]
				}
				add(strings.TrimSpace(rest))
			}
		}
		if dns, ok := strings.CutPrefix(line, "DNS:"); ok {
			add(strings.TrimSpace(dns))
		}
	}
	return out
}

func parseColonFields(output string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		i := strings.Index(line, ":")
		if i <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		val := strings.TrimSpace(line[i+1:])
		if key == "" || val == "" {
			continue
		}
		if _, exists := out[key]; !exists {
			out[key] = val
		}
	}
	return out
}

var notHostNames = map[string]bool{
	"SSL_Self_Signed_Fallback": true,
	"localhost":                true,
}

func addName(h *ingest.HostObs, name, source string, ident *identity) {

	name = strings.TrimSpace(strings.Trim(strings.ReplaceAll(name, `\x00`, ""), "\x00"))
	if name == "" || ident.names[name] || notHostNames[name] {
		return
	}
	ident.names[name] = true
	h.Hostnames = append(h.Hostnames, ingest.NameObs{Name: name, Source: source})
}

func setDomain(h *ingest.HostObs, candidates ...string) {
	if h.Domain != "" {
		return
	}
	for _, c := range candidates {
		if c != "" {
			h.Domain = c
			return
		}
	}
}
