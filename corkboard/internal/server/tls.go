package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func (s *Server) tlsConfig() (*tls.Config, error) {
	switch s.cfg.TLS.Mode {
	case "", "off":
		return nil, nil
	case "cert":
		cert, err := tls.LoadX509KeyPair(s.cfg.TLS.Cert, s.cfg.TLS.Key)
		if err != nil {
			return nil, fmt.Errorf("tls: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	case "auto":
		certFile := filepath.Join(s.dataDir, "tls", "cert.pem")
		keyFile := filepath.Join(s.dataDir, "tls", "key.pem")
		ips, dns := certSANs(s.cfg.Listen)
		if err := ensureAutoCert(certFile, keyFile, ips, dns, s.log); err != nil {
			return nil, err
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("tls: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	default:
		return nil, fmt.Errorf("tls: unknown mode %q", s.cfg.TLS.Mode)
	}
}

func certSANs(listen string) (ips []net.IP, dns []string) {
	ips = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	dns = []string{"localhost"}
	if h, err := os.Hostname(); err == nil && h != "" {
		dns = append(dns, h)
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
		ips = append(ips, ip)
		return ips, dns
	}

	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.IsGlobalUnicast() {
			ips = append(ips, ipnet.IP)
		}
	}
	return ips, dns
}

func ensureAutoCert(certFile, keyFile string, ips []net.IP, dns []string, log *slog.Logger) error {
	if _, err := os.Stat(certFile); err == nil {
		return nil
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("tls: generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return fmt.Errorf("tls: serial: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "corkboard", Organization: []string{"corkboard"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           ips,
		DNSNames:              dns,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("tls: create cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("tls: marshal key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return fmt.Errorf("tls: write key: %w", err)
	}
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return fmt.Errorf("tls: write cert: %w", err)
	}

	sum := sha256.Sum256(der)
	if log != nil {
		log.Info("generated self-signed TLS cert", "cert", certFile, "sha256", fmt.Sprintf("%x", sum[:]))
	}
	return nil
}
