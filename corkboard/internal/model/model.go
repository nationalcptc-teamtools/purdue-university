package model

import "strings"

import "corkboard/internal/ingest"

type Hostname struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

type Host struct {
	ID         int64  `json:"id"`
	IP         string `json:"ip"`
	OS         string `json:"os,omitempty"`
	OSAccuracy *int   `json:"os_accuracy,omitempty"`
	Domain     string `json:"domain,omitempty"`
	MAC        string `json:"mac,omitempty"`
	MACVendor  string `json:"mac_vendor,omitempty"`
	Status     string `json:"status"`
	Zone       string `json:"zone"`
	Owner      string `json:"owner,omitempty"`
	ClaimedAt  int64  `json:"claimed_at,omitempty"`
	Priority   int    `json:"priority"`
	FirstSeen  int64  `json:"first_seen"`
	LastSeen   int64  `json:"last_seen"`
	UpdatedAt  int64  `json:"updated_at"`

	Hostnames []Hostname        `json:"hostnames,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
	Services  int               `json:"services"`
	Explored  int               `json:"explored"`
	Claims    []TargetClaim     `json:"claims,omitempty"`
}

type TargetClaim struct {
	TargetID  int64  `json:"target_id"`
	Kind      string `json:"kind"`
	RefID     int64  `json:"id"`
	Label     string `json:"label"`
	Owner     string `json:"owner"`
	ClaimedAt int64  `json:"claimed_at"`
}

type Script struct {
	ID     string `json:"id"`
	Output string `json:"output"`
}

type Service struct {
	Method     string   `json:"method,omitempty"`
	Confidence int      `json:"confidence,omitempty"`
	ID         int64    `json:"id"`
	HostID     int64    `json:"host_id"`
	Proto      string   `json:"proto"`
	Port       int      `json:"port"`
	State      string   `json:"state"`
	Name       string   `json:"name,omitempty"`
	Product    string   `json:"product,omitempty"`
	Version    string   `json:"version,omitempty"`
	ExtraInfo  string   `json:"extrainfo,omitempty"`
	Tunnel     string   `json:"tunnel,omitempty"`
	CPE        []string `json:"cpe,omitempty"`
	Scripts    []Script `json:"scripts,omitempty"`
	FirstSeen  int64    `json:"first_seen"`
	LastSeen   int64    `json:"last_seen"`
	Type       string   `json:"type,omitempty"`
	ExploredAt *int64   `json:"explored_at,omitempty"`
	ExploredBy string   `json:"explored_by,omitempty"`
}

type WebResult struct {
	ID           int64    `json:"id"`
	HostID       *int64   `json:"host_id,omitempty"`
	ServiceID    *int64   `json:"service_id,omitempty"`
	URL          string   `json:"url"`
	FinalURL     string   `json:"final_url,omitempty"`
	StatusCode   int      `json:"status_code"`
	Title        string   `json:"title,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	TLSSubject   string   `json:"tls_subject,omitempty"`
	Screenshot   string   `json:"screenshot,omitempty"`
	Thumb        string   `json:"thumb,omitempty"`
	Failed       bool     `json:"failed"`
	FailedReason string   `json:"failed_reason,omitempty"`
	ProbedAt     int64    `json:"probed_at"`
	HostIP       string   `json:"host_ip,omitempty"`
	Owner        string   `json:"owner,omitempty"`
}

type Cred struct {
	ID         int64        `json:"id"`
	Domain     string       `json:"domain"`
	Username   string       `json:"username"`
	Secret     string       `json:"secret"`
	SecretType string       `json:"secret_type"`
	Source     string       `json:"source"`
	Notes      string       `json:"notes,omitempty"`
	AddedBy    string       `json:"added_by"`
	AddedAt    int64        `json:"added_at"`
	Access     []CredAccess `json:"access,omitempty"`
}

type CredAccess struct {
	HostID     int64  `json:"host_id"`
	IP         string `json:"ip"`
	Protocol   string `json:"protocol"`
	Level      string `json:"level"`
	ObservedAt int64  `json:"observed_at"`
}

type MatrixHost struct {
	ID int64  `json:"id"`
	IP string `json:"ip"`
}

type Share struct {
	ID         int64  `json:"id"`
	HostID     int64  `json:"host_id"`
	Name       string `json:"name"`
	Remark     string `json:"remark,omitempty"`
	CredID     *int64 `json:"cred_id,omitempty"`
	CanRead    bool   `json:"can_read"`
	CanWrite   bool   `json:"can_write"`
	ObservedAt int64  `json:"observed_at"`
}

type Task struct {
	ID         int64    `json:"id"`
	DedupeKey  string   `json:"dedupe_key"`
	RuleID     string   `json:"rule_id,omitempty"`
	HostID     *int64   `json:"host_id,omitempty"`
	ServiceID  *int64   `json:"service_id,omitempty"`
	Service    string   `json:"service,omitempty"`
	HostIP     string   `json:"host_ip,omitempty"`
	Title      string   `json:"title"`
	Body       string   `json:"body,omitempty"`
	Commands   []string `json:"commands,omitempty"`
	Priority   int      `json:"priority"`
	State      string   `json:"state"`
	Owner      string   `json:"owner,omitempty"`
	ClaimedAt  int64    `json:"claimed_at,omitempty"`
	CreatedAt  int64    `json:"created_at"`
	UpdatedAt  int64    `json:"updated_at"`
	ClosedNote string   `json:"closed_note,omitempty"`
}

type Finding struct {
	ID             int64         `json:"id"`
	DedupeKey      string        `json:"dedupe_key"`
	Title          string        `json:"title"`
	Severity       string        `json:"severity"`
	Source         string        `json:"source"`
	State          string        `json:"state"`
	GWLibraryTitle string        `json:"gw_library_title,omitempty"`
	Description    string        `json:"description,omitempty"`
	CreatedAt      int64         `json:"created_at"`
	UpdatedAt      int64         `json:"updated_at"`
	Hosts          []FindingHost `json:"hosts,omitempty"`
	NeedsReview    int64         `json:"needs_review"`
	ReportUpdate   bool          `json:"report_update"`
}

type FindingHost struct {
	HostID    int64  `json:"host_id"`
	IP        string `json:"ip"`
	ServiceID *int64 `json:"service_id,omitempty"`
	Evidence  string `json:"evidence,omitempty"`
}

type Compromise struct {
	ID           int64  `json:"id"`
	HostID       int64  `json:"host_id"`
	IP           string `json:"ip"`
	Level        string `json:"level"`
	ViaFindingID *int64 `json:"via_finding_id,omitempty"`
	ViaCredID    *int64 `json:"via_cred_id,omitempty"`
	ViaText      string `json:"via_text,omitempty"`
	ByUser       string `json:"by_user"`
	At           int64  `json:"at"`
}

type Note struct {
	ID        int64  `json:"id"`
	HostID    int64  `json:"host_id"`
	ServiceID *int64 `json:"service_id,omitempty"`
	Service   string `json:"service,omitempty"`
	Author    string `json:"author"`
	Body      string `json:"body"`
	Outcome   string `json:"outcome,omitempty"`
	Command   string `json:"command,omitempty"`
	Output    string `json:"output,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

type Event struct {
	ID      int64  `json:"id"`
	At      int64  `json:"at"`
	Actor   string `json:"actor"`
	Kind    string `json:"kind"`
	HostID  *int64 `json:"host_id,omitempty"`
	RefID   *int64 `json:"ref_id,omitempty"`
	Summary string `json:"summary"`
	Data    string `json:"data,omitempty"`
}

type HostDetail struct {
	ScanHistory []ScanRecord        `json:"scan_history,omitempty"`
	OSEvidence  []ingest.OSEvidence `json:"os_evidence,omitempty"`
	Host        Host                `json:"host"`
	Services    []Service           `json:"services"`
	HostScripts []Script            `json:"host_scripts,omitempty"`
	Web         []WebResult         `json:"web"`
	Creds       []Cred              `json:"creds"`
	Shares      []Share             `json:"shares"`
	Tasks       []Task              `json:"tasks"`
	Notes       []Note              `json:"notes"`
	Compromises []Compromise        `json:"compromises"`
	Timeline    []Event             `json:"timeline"`
}

type CoverageCell struct {
	Status string `json:"status,omitempty"`
	Done   bool   `json:"done"`
	At     int64  `json:"at,omitempty"`
	Actor  string `json:"actor,omitempty"`
}

type ScanRecord struct {
	RunID   int64          `json:"run_id"`
	IP      string         `json:"ip"`
	HostID  *int64         `json:"host_id,omitempty"`
	Vantage string         `json:"vantage"`
	At      int64          `json:"observed_at"`
	Run     ingest.RunInfo `json:"run"`
	Host    ingest.HostObs `json:"host"`
}

type HostCoverage struct {
	HostID int64                   `json:"host_id"`
	IP     string                  `json:"ip"`
	Zone   string                  `json:"zone"`
	Stages map[string]CoverageCell `json:"stages"`
}

func CredName(domain, user string) string {
	if domain == "" {
		return user
	}
	return domain + "\\" + user
}

func BestHostname(names []Hostname) string {
	if len(names) == 0 {
		return ""
	}
	best := names[0].Name
	for _, n := range names[1:] {
		if strings.Count(n.Name, ".") > strings.Count(best, ".") {
			best = n.Name
		}
	}
	return best
}
