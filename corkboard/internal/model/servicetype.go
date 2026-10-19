package model

import "strings"

var serviceTypes = map[string]string{
	"http": "web", "https": "web", "http-proxy": "web", "http-alt": "web", "https-alt": "web", "ssl/http": "web",
	"microsoft-ds": "smb", "netbios-ssn": "smb", "smb": "smb",
	"msrpc": "rpc", "ncacn_http": "rpc", "rpcbind": "rpc",
	"ms-wbt-server": "rdp", "rdp": "rdp",
	"wsman": "winrm", "wsmans": "winrm", "winrm": "winrm",
	"ssh":  "ssh",
	"ldap": "ldap", "ldaps": "ldap", "globalcatldap": "ldap", "globalcatldapssl": "ldap", "adws": "ldap",
	"kerberos-sec": "kerberos", "kerberos": "kerberos", "kpasswd5": "kerberos", "kpasswd": "kerberos",
	"domain":   "dns",
	"ms-sql-s": "db", "mysql": "db", "postgresql": "db", "oracle-tns": "db", "redis": "db", "mongodb": "db",
	"smtp": "mail", "submission": "mail", "smtps": "mail", "imap": "mail", "imaps": "mail", "pop3": "mail", "pop3s": "mail",
	"ftp": "ftp", "ftps": "ftp",
	"snmp":   "snmp",
	"vnc":    "vnc",
	"telnet": "telnet",
	"nfs":    "nfs", "mountd": "nfs",
}

var portTypes = map[int]string{
	80: "web", 443: "web", 8080: "web", 8443: "web",
	139: "smb", 445: "smb", 135: "rpc", 3389: "rdp", 22: "ssh",
	389: "ldap", 636: "ldap", 3268: "ldap", 3269: "ldap", 9389: "ldap",
	88: "kerberos", 464: "kerberos", 53: "dns",
	1433: "db", 3306: "db", 5432: "db", 1521: "db", 6379: "db", 27017: "db",
	25: "mail", 587: "mail", 143: "mail", 993: "mail", 110: "mail", 995: "mail",
	21: "ftp", 161: "snmp", 5900: "vnc", 23: "telnet", 2049: "nfs",
}

func ServiceType(s Service) string {
	switch s.Port {
	case 5985, 5986, 47001:
		if s.Proto == "tcp" {
			return "winrm"
		}
	}
	name := strings.ToLower(s.Name)
	if t, ok := serviceTypes[name]; ok {
		return t
	}
	if strings.HasPrefix(name, "http") || (s.Tunnel == "ssl" && strings.Contains(name, "http")) {
		return "web"
	}
	if s.Proto == "tcp" && s.Port >= 49152 && (name == "" || name == "unknown") {
		return "rpc"
	}
	if t, ok := portTypes[s.Port]; ok && (name == "" || name == "unknown") {
		return t
	}
	return "other"
}
