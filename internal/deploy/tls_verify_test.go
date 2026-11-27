package deploy

import (
	"testing"

	"ssl-center/internal/model"
)

func TestResolveTLSVerifyTarget(t *testing.T) {
	tests := []struct {
		name     string
		cert     *model.Certificate
		dep      *model.Deployment
		host     *model.Host
		wantHost string
		wantPort int
		wantSNI  string
	}{
		{
			name: "local host uses explicit TLS SNI when verify host empty",
			cert: &model.Certificate{Domain: "ypank.com"},
			dep: &model.Deployment{
				TLSVerifySNI:  "status.ypank.com",
				TLSVerifyPort: 443,
			},
			host: &model.Host{
				IsLocal: true,
				Mode:    model.HostModeLocal,
				Host:    "localhost",
			},
			wantHost: "status.ypank.com",
			wantPort: 443,
			wantSNI:  "status.ypank.com",
		},
		{
			name: "local host wildcard uses non-wildcard SAN for both host and SNI",
			cert: &model.Certificate{
				Domain:   "*.ypank.com",
				SANsJSON: `["status.ypank.com"]`,
			},
			dep: &model.Deployment{},
			host: &model.Host{
				IsLocal: true,
				Mode:    model.HostModeLocal,
				Host:    "localhost",
			},
			wantHost: "status.ypank.com",
			wantPort: 443,
			wantSNI:  "status.ypank.com",
		},
		{
			name: "local host honors explicit verify host",
			cert: &model.Certificate{Domain: "ypank.com"},
			dep: &model.Deployment{
				TLSVerifyHost: "123.254.106.182",
				TLSVerifySNI:  "status.ypank.com",
				TLSVerifyPort: 8443,
			},
			host: &model.Host{
				IsLocal: true,
				Mode:    model.HostModeLocal,
				Host:    "localhost",
			},
			wantHost: "123.254.106.182",
			wantPort: 8443,
			wantSNI:  "status.ypank.com",
		},
		{
			name: "remote ssh host dials ssh host IP while keeping TLS SNI",
			cert: &model.Certificate{Domain: "ypank.com"},
			dep: &model.Deployment{
				TLSVerifySNI: "status.ypank.com",
			},
			host: &model.Host{
				IsLocal: false,
				Mode:    model.HostModeSSH,
				Host:    "10.0.0.5",
			},
			wantHost: "10.0.0.5",
			wantPort: 443,
			wantSNI:  "status.ypank.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotHost, gotPort, gotSNI := resolveTLSVerifyTarget(tc.cert, tc.dep, tc.host)
			if gotHost != tc.wantHost || gotPort != tc.wantPort || gotSNI != tc.wantSNI {
				t.Fatalf("resolveTLSVerifyTarget() = (%q, %d, %q), want (%q, %d, %q)",
					gotHost, gotPort, gotSNI, tc.wantHost, tc.wantPort, tc.wantSNI)
			}
		})
	}
}
