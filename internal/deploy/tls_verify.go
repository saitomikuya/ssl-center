package deploy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"ssl-center/internal/model"
)

const defaultTLSDialTimeout = 10 * time.Second

// ErrTLSFingerprintMismatch indicates the live TLS leaf certificate SHA-256 fingerprint
// does not match the expected certificate fingerprint.
var ErrTLSFingerprintMismatch = errors.New("tls leaf certificate fingerprint mismatch")

// VerifyTLSFingerprint performs a lightweight TLS handshake against hostAddr:port with ServerName,
// extracts the leaf certificate (PeerCertificates[0].Raw) SHA-256 lowercase hex fingerprint,
// and compares it strictly against expectedFP.
func VerifyTLSFingerprint(ctx context.Context, hostAddr string, port int, serverName string, expectedFP string) (string, error) {
	hostAddr = strings.TrimSpace(hostAddr)
	if hostAddr == "" {
		return "", errors.New("tls verify host is empty")
	}
	if port <= 0 {
		port = 443
	}
	expectedFP = strings.ToLower(strings.TrimSpace(expectedFP))
	if expectedFP == "" {
		return "", errors.New("expected certificate fingerprint is empty")
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: defaultTLSDialTimeout},
		Config: &tls.Config{
			ServerName:         strings.TrimSpace(serverName),
			InsecureSkipVerify: true, // Verified explicitly via leaf SHA-256 fingerprint below.
		},
	}

	addr := net.JoinHostPort(hostAddr, strconv.Itoa(port))
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("tls dial %s (sni %q): %w", addr, serverName, err)
	}
	defer rawConn.Close()

	tlsConn, ok := rawConn.(*tls.Conn)
	if !ok {
		return "", errors.New("unexpected non-TLS connection")
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("tls peer %s presented no certificates", addr)
	}

	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	observedFP := strings.ToLower(hex.EncodeToString(sum[:]))

	if observedFP != expectedFP {
		return observedFP, fmt.Errorf("%w: observed %s != expected %s", ErrTLSFingerprintMismatch, observedFP, expectedFP)
	}
	return observedFP, nil
}

func resolveTLSVerifyTarget(cert *model.Certificate, dep *model.Deployment, host *model.Host) (verifyHost string, verifyPort int, verifySNI string) {
	verifyHost = strings.TrimSpace(dep.TLSVerifyHost)
	if verifyHost == "" {
		if host != nil && strings.TrimSpace(host.Host) != "" && !isLocalHost(host) {
			verifyHost = strings.TrimSpace(host.Host)
		} else if cert != nil {
			verifyHost = strings.TrimPrefix(strings.TrimSpace(cert.Domain), "*.")
		}
	}

	verifyPort = dep.TLSVerifyPort
	if verifyPort <= 0 {
		verifyPort = 443
	}

	verifySNI = strings.TrimSpace(dep.TLSVerifySNI)
	if verifySNI == "" {
		if cert != nil && strings.TrimSpace(cert.Domain) != "" {
			dom := strings.TrimSpace(cert.Domain)
			if !strings.HasPrefix(dom, "*.") {
				verifySNI = dom
			} else {
				verifySNI = pickNonWildcardSAN(cert.SANsJSON)
				if verifySNI == "" {
					verifySNI = strings.TrimPrefix(dom, "*.")
				}
			}
		} else {
			verifySNI = verifyHost
		}
	}
	return verifyHost, verifyPort, verifySNI
}

func pickNonWildcardSAN(sansJSON string) string {
	if strings.TrimSpace(sansJSON) == "" {
		return ""
	}
	var sans []string
	if err := json.Unmarshal([]byte(sansJSON), &sans); err != nil {
		return ""
	}
	for _, s := range sans {
		s = strings.TrimSpace(s)
		if s != "" && !strings.HasPrefix(s, "*.") {
			return s
		}
	}
	return ""
}
