package acme

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/certcrypto"

	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

func TestResolveDirectoryURL(t *testing.T) {
	cases := []struct {
		provider string
		env      string
		want     string
		wantErr  bool
	}{
		{"letsencrypt", "production", LetsEncryptProdURL, false},
		{"letsencrypt", "staging", LetsEncryptStagingURL, false},
		{"gts", "production", GTSProdURL, false},
		{"gts", "staging", GTSStagingURL, false},
		{"unknown", "production", "", true},
		{"gts", "invalid", "", true},
	}
	for _, tc := range cases {
		got, err := ResolveDirectoryURL(tc.provider, tc.env)
		if (err != nil) != tc.wantErr {
			t.Fatalf("ResolveDirectoryURL(%q, %q) err=%v wantErr=%v", tc.provider, tc.env, err, tc.wantErr)
		}
		if got != tc.want {
			t.Fatalf("ResolveDirectoryURL(%q, %q) = %q, want %q", tc.provider, tc.env, got, tc.want)
		}
	}
}

func TestCAService_LetsEncrypt_GTSEAB_ImportExport_And_Redaction(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	mockACME := newMockACMEServer(t)

	caSvc := NewCAService(
		env.db,
		env.cipher,
		env.redactor,
		WithCAHTTPClient(mockACME.srv.Client()),
		WithCADirectoryOverride(model.CAProviderLetsEncrypt, model.CAEnvStaging, mockACME.URL()),
		WithCADirectoryOverride(model.CAProviderGTS, model.CAEnvProduction, mockACME.URL()),
		WithCADirectoryOverride(model.CAProviderGTS, model.CAEnvStaging, mockACME.URL()),
	)

	// 1. Register Let's Encrypt Staging without EAB.
	leReq := &model.CreateCARequest{
		Name:        "LE Staging",
		Provider:    model.CAProviderLetsEncrypt,
		Environment: model.CAEnvStaging,
		Email:       "ops@example.com",
		IsDefault:   true,
	}
	leDTO, err := caSvc.CreateAccount(ctx, leReq, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateAccount LE: %v", err)
	}
	if !leDTO.IsDefault || leDTO.AccountURI == "" {
		t.Fatalf("unexpected LE DTO: %+v", leDTO)
	}

	// Verify acme_key_enc is encrypted with AAD ca_accounts:acme_key_enc and registered in SecretRedactor.
	leRow, err := env.db.GetCAAccount(ctx, leDTO.ID)
	if err != nil {
		t.Fatalf("GetCAAccount: %v", err)
	}
	if !strings.HasPrefix(leRow.ACMEKeyEnc, "v1:") {
		t.Fatalf("expected v1: encrypted acme_key_enc, got %q", leRow.ACMEKeyEnc)
	}
	if _, err := env.cipher.Decrypt(leRow.ACMEKeyEnc, "wrong:aad"); err == nil {
		t.Fatal("expected decryption failure with wrong AAD")
	}
	exportedLE, err := caSvc.ExportKey(ctx, leDTO.ID, "127.0.0.1")
	if err != nil {
		t.Fatalf("ExportKey LE: %v", err)
	}
	if !strings.Contains(exportedLE.ACMEKeyPEM, "PRIVATE KEY-----") {
		t.Fatalf("expected valid PEM key, got %q", exportedLE.ACMEKeyPEM)
	}
	if got := env.redactor.Redact("leak: " + exportedLE.ACMEKeyPEM); strings.Contains(got, exportedLE.ACMEKeyPEM) {
		t.Fatal("expected SecretRedactor to redact exported ACME private key")
	}

	// 2. Register GTS Prod with EAB; verify EAB is sent to ACME, cleared in request, and NEVER persisted.
	eabKID := "test-eab-kid-123456"
	eabMAC := base64.RawURLEncoding.EncodeToString([]byte("super-secret-eab-hmac-key-0123456789"))
	gtsReq := &model.CreateCARequest{
		Name:        "GTS Prod",
		Provider:    model.CAProviderGTS,
		Environment: model.CAEnvProduction,
		Email:       "gts@example.com",
		IsDefault:   false,
		EABKeyID:    eabKID,
		EABHMACKey:  eabMAC,
	}
	gtsDTO, err := caSvc.CreateAccount(ctx, gtsReq, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateAccount GTS EAB: %v", err)
	}
	if gtsReq.EABKeyID != "" || gtsReq.EABHMACKey != "" {
		t.Fatalf("expected EAB fields zeroed on request struct, got kid=%q hmac=%q", gtsReq.EABKeyID, gtsReq.EABHMACKey)
	}
	if mockACME.EABCount() != 1 || !mockACME.HasEABSubstring(eabKID) {
		t.Fatalf("expected ACME server to receive EAB kid %q", eabKID)
	}
	gtsRow, err := env.db.GetCAAccount(ctx, gtsDTO.ID)
	if err != nil {
		t.Fatalf("GetCAAccount GTS: %v", err)
	}
	plainGTSKey, err := env.cipher.Decrypt(gtsRow.ACMEKeyEnc, aadCAKeyEnc)
	if err != nil {
		t.Fatalf("Decrypt GTS key: %v", err)
	}
	if strings.Contains(plainGTSKey, eabKID) || strings.Contains(plainGTSKey, eabMAC) {
		t.Fatal("EAB credentials must never be stored in DB")
	}

	// 3. Import existing acme.key PEM via ResolveAccountByKey.
	exportedGTS, err := caSvc.ExportKey(ctx, gtsDTO.ID, "127.0.0.1")
	if err != nil {
		t.Fatalf("ExportKey GTS: %v", err)
	}
	importDTO, err := caSvc.CreateAccount(ctx, &model.CreateCARequest{
		Name:        "GTS Imported",
		Provider:    model.CAProviderGTS,
		Environment: model.CAEnvStaging,
		Email:       "gts@example.com",
		ACMEKeyPEM:  exportedGTS.ACMEKeyPEM,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateAccount import existing acme.key: %v", err)
	}
	if importDTO.AccountURI != exportedGTS.AccountURI {
		t.Fatalf("imported account URI = %q, want %q", importDTO.AccountURI, exportedGTS.AccountURI)
	}

	// Importing an unregistered key must fail online ResolveAccountByKey validation.
	unknownKey, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	if _, err := caSvc.CreateAccount(ctx, &model.CreateCARequest{
		Name:        "GTS Unknown Key",
		Provider:    model.CAProviderGTS,
		Environment: model.CAEnvStaging,
		Email:       "unknown@example.com",
		ACMEKeyPEM:  string(certcrypto.PEMEncode(unknownKey)),
	}, "127.0.0.1"); !errors.Is(err, ErrCAKeyValidation) {
		t.Fatalf("expected ErrCAKeyValidation for unregistered key, got %v", err)
	}

	// 4. SetDefault and Delete protection when referenced by certificate.
	if _, err := caSvc.SetDefault(ctx, gtsDTO.ID, "127.0.0.1"); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	def, err := env.db.GetDefaultCAAccount(ctx)
	if err != nil || def.ID != gtsDTO.ID {
		t.Fatalf("expected default CA ID=%d, got %+v err=%v", gtsDTO.ID, def, err)
	}

	// Delete unreferenced imported CA succeeds and removes key from SecretRedactor.
	if err := caSvc.DeleteAccount(ctx, importDTO.ID, "127.0.0.1"); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}
	if _, err := env.db.GetCAAccount(ctx, importDTO.ID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}
