package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"ssl-center/internal/config"
	"ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

const (
	ManifestVersion       = 1
	DefaultAppVersion     = "1.0.0"
	DefaultMaxBackupBytes = 512 << 20 // 512 MiB compressed upload limit
	maxUncompressedBytes  = 1 << 30   // 1 GiB uncompressed extraction limit
	maxArchiveEntries     = 10000
)

var expectedTables = []string{
	"audit_events",
	"ca_accounts",
	"caddy_snapshots",
	"cert_jobs",
	"certificates",
	"deploy_logs",
	"deployments",
	"dns_credentials",
	"hosts",
	"sessions",
	"settings",
	"webhooks",
}

// ValidationError represents a client-side invalid/corrupted/unsafe backup archive.
type ValidationError struct {
	Message string
	Cause   error
}

func (e *ValidationError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *ValidationError) Unwrap() error {
	return e.Cause
}

// Service implements full .tar.gz backup export and verified atomic restore.
type Service struct {
	cfg        *config.Config
	db         *db.DB
	cipher     *crypto.Cipher
	redactor   *crypto.SecretRedactor
	maint      model.MaintenanceCoordinator
	reloader   model.ScheduleReloader
	appVersion string
	clock      func() time.Time
}

// NewService constructs a backup Service.
func NewService(
	cfg *config.Config,
	database *db.DB,
	cipher *crypto.Cipher,
	redactor *crypto.SecretRedactor,
	maint model.MaintenanceCoordinator,
	reloader model.ScheduleReloader,
) *Service {
	return &Service{
		cfg:        cfg,
		db:         database,
		cipher:     cipher,
		redactor:   redactor,
		maint:      maint,
		reloader:   reloader,
		appVersion: DefaultAppVersion,
		clock:      func() time.Time { return time.Now().UTC() },
	}
}

// ExportBackup exports an atomic SQLite snapshot (with sessions cleared), master.key,
// certs/, and a SHA-256 manifest.json into a .tar.gz stream written to w.
func (s *Service) ExportBackup(ctx context.Context, w io.Writer) error {
	if err := os.MkdirAll(s.cfg.TmpDir(), 0o700); err != nil {
		return fmt.Errorf("ensure tmp dir: %w", err)
	}
	workDir, err := os.MkdirTemp(s.cfg.TmpDir(), "backup-export-*")
	if err != nil {
		return fmt.Errorf("create export temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(workDir) }()

	expDBPath := filepath.Join(workDir, "app.db")
	if err := s.db.ExportVacuumInto(ctx, expDBPath); err != nil {
		return fmt.Errorf("export sqlite snapshot: %w", err)
	}

	masterKeyData, err := os.ReadFile(s.cfg.MasterKeyPath())
	if err != nil {
		return fmt.Errorf("read master.key: %w", err)
	}
	if len(masterKeyData) != crypto.MasterKeySize {
		return fmt.Errorf("invalid master.key size: got %d, want %d", len(masterKeyData), crypto.MasterKeySize)
	}
	masterKeyStagePath := filepath.Join(workDir, "master.key")
	if err := os.WriteFile(masterKeyStagePath, masterKeyData, 0o600); err != nil {
		crypto.ZeroBytes(masterKeyData)
		return fmt.Errorf("stage master.key: %w", err)
	}
	crypto.ZeroBytes(masterKeyData)

	type archiveItem struct {
		relPath string
		fsPath  string
		mode    int64
		sha256  string
		size    int64
	}

	var items []archiveItem
	filesMap := make(map[string]string)

	addFile := func(relPath, fsPath string, mode int64) error {
		sum, size, err := hashAndSizeFile(fsPath)
		if err != nil {
			return err
		}
		items = append(items, archiveItem{
			relPath: relPath,
			fsPath:  fsPath,
			mode:    mode,
			sha256:  sum,
			size:    size,
		})
		filesMap[relPath] = sum
		return nil
	}

	if err := addFile("app.db", expDBPath, 0o600); err != nil {
		return fmt.Errorf("hash exported app.db: %w", err)
	}
	if err := addFile("master.key", masterKeyStagePath, 0o600); err != nil {
		return fmt.Errorf("hash staged master.key: %w", err)
	}

	certsDir := s.cfg.CertsDir()
	if info, statErr := os.Stat(certsDir); statErr == nil && info.IsDir() {
		err := filepath.WalkDir(certsDir, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(certsDir, p)
			if err != nil {
				return err
			}
			arcRel := path.Clean("certs/" + filepath.ToSlash(rel))
			if strings.HasPrefix(arcRel, "..") || strings.HasPrefix(arcRel, "/") {
				return fmt.Errorf("unsafe cert path %q", arcRel)
			}
			mode := int64(0o644)
			if strings.HasSuffix(d.Name(), "privkey.pem") {
				mode = 0o600
			}
			return addFile(arcRel, p, mode)
		})
		if err != nil {
			return fmt.Errorf("walk certs dir: %w", err)
		}
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].relPath < items[j].relPath
	})

	manifest := model.BackupManifest{
		Version:    ManifestVersion,
		AppVersion: s.appVersion,
		CreatedAt:  s.clock().UTC(),
		Files:      filesMap,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest.json: %w", err)
	}

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	// Write manifest.json first
	if err := tw.WriteHeader(&tar.Header{
		Name:     "manifest.json",
		Mode:     0o644,
		Size:     int64(len(manifestBytes)),
		ModTime:  manifest.CreatedAt,
		Typeflag: tar.TypeReg,
	}); err != nil {
		_ = tw.Close()
		_ = gz.Close()
		return err
	}
	if _, err := tw.Write(manifestBytes); err != nil {
		_ = tw.Close()
		_ = gz.Close()
		return err
	}

	for _, item := range items {
		if err := tw.WriteHeader(&tar.Header{
			Name:     item.relPath,
			Mode:     item.mode,
			Size:     item.size,
			ModTime:  manifest.CreatedAt,
			Typeflag: tar.TypeReg,
		}); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return err
		}
		f, err := os.Open(item.fsPath)
		if err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return err
		}
		_, copyErr := io.Copy(tw, f)
		_ = f.Close()
		if copyErr != nil {
			_ = tw.Close()
			_ = gz.Close()
			return copyErr
		}
	}

	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return err
	}
	return gz.Close()
}

// RestoreBackup validates and atomically restores a .tar.gz backup archive.
func (s *Service) RestoreBackup(ctx context.Context, r io.Reader, maxBytes int64, actorIP string) (*model.RestoreResult, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBackupBytes
	}
	if err := os.MkdirAll(s.cfg.TmpDir(), 0o700); err != nil {
		return nil, fmt.Errorf("ensure tmp dir: %w", err)
	}
	stageDir, err := os.MkdirTemp(s.cfg.TmpDir(), "backup-restore-*")
	if err != nil {
		return nil, fmt.Errorf("create restore stage dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(stageDir) }()

	// 1. Safely extract upload with strict anti-Tar-Slip & symlink/special-file rejection.
	extractedHashes, err := extractArchiveSafely(r, stageDir, maxBytes)
	if err != nil {
		return nil, err
	}

	// 2. Validate manifest.json version & every SHA-256 checksum.
	manifestPath := filepath.Join(stageDir, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, &ValidationError{Message: "backup archive missing manifest.json", Cause: err}
	}
	var manifest model.BackupManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, &ValidationError{Message: "invalid manifest.json", Cause: err}
	}
	if manifest.Version != ManifestVersion {
		return nil, &ValidationError{Message: fmt.Sprintf("unsupported backup manifest version %d (expected %d)", manifest.Version, ManifestVersion)}
	}
	if _, ok := manifest.Files["app.db"]; !ok {
		return nil, &ValidationError{Message: "manifest.json missing app.db entry"}
	}
	if _, ok := manifest.Files["master.key"]; !ok {
		return nil, &ValidationError{Message: "manifest.json missing master.key entry"}
	}

	for relPath, expectedHex := range manifest.Files {
		cleaned, safeErr := sanitizeArchivePath(relPath, false)
		if safeErr != nil || cleaned != relPath {
			return nil, &ValidationError{Message: fmt.Sprintf("unsafe manifest file path %q", relPath)}
		}
		gotHex, ok := extractedHashes[cleaned]
		if !ok {
			return nil, &ValidationError{Message: fmt.Sprintf("backup archive missing file %q listed in manifest", cleaned)}
		}
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(expectedHex)), []byte(gotHex)) != 1 {
			return nil, &ValidationError{Message: fmt.Sprintf("checksum mismatch for %q", cleaned)}
		}
	}
	for extractedPath := range extractedHashes {
		if extractedPath == "manifest.json" {
			continue
		}
		if _, listed := manifest.Files[extractedPath]; !listed {
			return nil, &ValidationError{Message: fmt.Sprintf("unexpected unlisted file %q in backup archive", extractedPath)}
		}
	}

	// 3. Validate candidate master.key and candidate app.db (integrity_check + 12 tables + test-decrypt).
	candKeyPath := filepath.Join(stageDir, "master.key")
	candKey, err := os.ReadFile(candKeyPath)
	if err != nil {
		return nil, &ValidationError{Message: "failed to read candidate master.key", Cause: err}
	}
	defer crypto.ZeroBytes(candKey)
	if len(candKey) != crypto.MasterKeySize {
		return nil, &ValidationError{Message: fmt.Sprintf("invalid candidate master.key length %d", len(candKey))}
	}
	candCipher, err := crypto.NewCipher(candKey)
	if err != nil {
		return nil, &ValidationError{Message: "failed to initialize candidate cipher", Cause: err}
	}

	candDBPath := filepath.Join(stageDir, "app.db")
	if err := validateCandidateSQLite(ctx, candDBPath, candCipher); err != nil {
		return nil, err
	}

	// 4. Acquire global maintenance lock (strictly defer EndMaintenance AFTER err == nil).
	if s.maint != nil {
		if err := s.maint.BeginMaintenance(ctx); err != nil {
			return nil, fmt.Errorf("begin maintenance mode: %w", err)
		}
		defer s.maint.EndMaintenance()
	}

	// 5. Move/snapshot existing live data to <DATA_DIR>/pre_restore_<ts>/
	now := s.clock().UTC()
	ts := now.Format("20060102T150405Z")
	preDir := filepath.Join(s.cfg.DataDir, "pre_restore_"+ts)
	if _, statErr := os.Stat(preDir); statErr == nil {
		preDir = fmt.Sprintf("%s_%d", preDir, now.UnixNano()%1000000)
	}
	if err := os.MkdirAll(preDir, 0o700); err != nil {
		return nil, fmt.Errorf("create pre_restore dir: %w", err)
	}

	liveMasterPath := s.cfg.MasterKeyPath()
	preMasterPath := filepath.Join(preDir, "master.key")
	hadMasterKey := false
	if _, err := os.Stat(liveMasterPath); err == nil {
		if copyErr := copyFileWithMode(liveMasterPath, preMasterPath, 0o600); copyErr != nil {
			return nil, fmt.Errorf("backup existing master.key: %w", copyErr)
		}
		hadMasterKey = true
	}

	liveCertsDir := s.cfg.CertsDir()
	preCertsDir := filepath.Join(preDir, "certs")
	hadCertsDir := false
	if info, err := os.Stat(liveCertsDir); err == nil && info.IsDir() {
		if moveErr := moveDir(liveCertsDir, preCertsDir); moveErr != nil {
			return nil, fmt.Errorf("backup existing certs dir: %w", moveErr)
		}
		hadCertsDir = true
	}

	restoreMasterAndCerts := func() {
		if hadMasterKey {
			if oldKey, err := os.ReadFile(preMasterPath); err == nil {
				_ = crypto.WriteMasterKeyAtomic(liveMasterPath, oldKey)
				crypto.ZeroBytes(oldKey)
			}
		}
		_ = os.RemoveAll(liveCertsDir)
		if hadCertsDir {
			_ = moveDir(preCertsDir, liveCertsDir)
		}
	}

	// 6. Atomically swap master.key (0600), certs/, and app.db via db.SwapDB.
	if err := crypto.WriteMasterKeyAtomic(liveMasterPath, candKey); err != nil {
		restoreMasterAndCerts()
		return nil, fmt.Errorf("install restored master.key: %w", err)
	}

	stageCertsDir := filepath.Join(stageDir, "certs")
	if info, err := os.Stat(stageCertsDir); err == nil && info.IsDir() {
		if moveErr := moveDir(stageCertsDir, liveCertsDir); moveErr != nil {
			restoreMasterAndCerts()
			return nil, fmt.Errorf("install restored certs dir: %w", moveErr)
		}
	} else {
		if mkErr := os.MkdirAll(liveCertsDir, 0o755); mkErr != nil {
			restoreMasterAndCerts()
			return nil, fmt.Errorf("create empty certs dir: %w", mkErr)
		}
	}

	preDBPath := filepath.Join(preDir, "app.db")
	if err := s.db.SwapDB(func(dbPath string) error {
		hadOldDB := false
		if _, statErr := os.Stat(dbPath); statErr == nil {
			if copyErr := copyFileWithMode(dbPath, preDBPath, 0o600); copyErr != nil {
				return fmt.Errorf("snapshot existing app.db to pre_restore: %w", copyErr)
			}
			hadOldDB = true
		}

		if err := installFileAtomic(candDBPath, dbPath, 0o600); err != nil {
			if hadOldDB {
				_ = installFileAtomic(preDBPath, dbPath, 0o600)
			}
			return fmt.Errorf("install restored app.db: %w", err)
		}
		return nil
	}); err != nil {
		restoreMasterAndCerts()
		return nil, fmt.Errorf("swap database: %w", err)
	}

	// 7. Reload cipher key, re-hydrate SecretRedactor, clear sessions, reload schedule.
	if err := s.cipher.ReloadKey(candKey); err != nil {
		return nil, fmt.Errorf("reload cipher key: %w", err)
	}
	if s.redactor != nil {
		secrets, err := CollectAllSecrets(ctx, s.db, s.cipher)
		if err != nil {
			return nil, fmt.Errorf("reload secret redactor: %w", err)
		}
		s.redactor.ReplaceAll(secrets)
	}
	if err := s.db.DeleteAllSessions(ctx); err != nil {
		return nil, fmt.Errorf("clear restored sessions: %w", err)
	}
	if s.reloader != nil {
		_ = s.reloader.ReloadSchedule(ctx)
	}

	_, _ = s.db.CreateAuditEvent(ctx, &model.AuditEvent{
		EventType:  "system.backup_restored",
		Level:      model.AuditLevelWarn,
		TargetType: "system",
		TargetName: "backup",
		Message:    fmt.Sprintf("System restored from backup (pre-restore saved at %s)", filepath.Base(preDir)),
		ActorIP:    actorIP,
	})

	return &model.RestoreResult{
		RestoredAt:      now,
		PreRestoreDir:   preDir,
		ReloginRequired: true,
		Message:         "Backup restored successfully. Please sign in with the administrator password from the restored backup.",
	}, nil
}

// CollectAllSecrets decrypts all persisted secret values from the database for SecretRedactor hydration.
func CollectAllSecrets(ctx context.Context, database *db.DB, cipher *crypto.Cipher) ([]string, error) {
	if cipher == nil {
		return nil, errors.New("cipher is nil")
	}
	var secrets []string
	addSecret := func(v string) {
		if v != "" {
			secrets = append(secrets, v)
		}
	}

	cas, err := database.ListCAAccounts(ctx)
	if err != nil {
		return nil, err
	}
	for _, ca := range cas {
		if ca.ACMEKeyEnc != "" {
			plain, err := cipher.Decrypt(ca.ACMEKeyEnc, "ca_accounts:acme_key_enc")
			if err != nil {
				return nil, fmt.Errorf("decrypt ca_accounts(%d): %w", ca.ID, err)
			}
			addSecret(plain)
		}
	}

	dnsList, err := database.ListDNSCredentials(ctx)
	if err != nil {
		return nil, err
	}
	for _, dns := range dnsList {
		if dns.ConfigEnc != "" {
			plain, err := cipher.Decrypt(dns.ConfigEnc, "dns_credentials:config_enc")
			if err != nil {
				return nil, fmt.Errorf("decrypt dns_credentials(%d): %w", dns.ID, err)
			}
			addSecret(plain)
			var cf model.CloudflareCredConfig
			if json.Unmarshal([]byte(plain), &cf) == nil {
				addSecret(cf.APIToken)
			}
			var hw model.HuaweiCredConfig
			if json.Unmarshal([]byte(plain), &hw) == nil {
				addSecret(hw.AccessKey)
				addSecret(hw.SecretKey)
			}
		}
	}

	hosts, err := database.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		if h.SSHPrivateKeyEnc != "" {
			plain, err := cipher.Decrypt(h.SSHPrivateKeyEnc, "hosts:ssh_private_key_enc")
			if err != nil {
				return nil, fmt.Errorf("decrypt hosts(%d) key: %w", h.ID, err)
			}
			addSecret(plain)
		}
		if h.SSHPassphraseEnc != "" {
			plain, err := cipher.Decrypt(h.SSHPassphraseEnc, "hosts:ssh_passphrase_enc")
			if err != nil {
				return nil, fmt.Errorf("decrypt hosts(%d) passphrase: %w", h.ID, err)
			}
			addSecret(plain)
		}
		if h.SSHPasswordEnc != "" {
			plain, err := cipher.Decrypt(h.SSHPasswordEnc, "hosts:ssh_password_enc")
			if err != nil {
				return nil, fmt.Errorf("decrypt hosts(%d) password: %w", h.ID, err)
			}
			addSecret(plain)
		}
	}

	webhooks, err := database.ListWebhooks(ctx)
	if err != nil {
		return nil, err
	}
	for _, wh := range webhooks {
		if wh.HeadersEnc != "" {
			plain, err := cipher.Decrypt(wh.HeadersEnc, "webhooks:headers_enc")
			if err != nil {
				return nil, fmt.Errorf("decrypt webhooks(%d) headers: %w", wh.ID, err)
			}
			var hdrs map[string]string
			if json.Unmarshal([]byte(plain), &hdrs) == nil {
				for _, val := range hdrs {
					addSecret(val)
				}
			}
		}
		if wh.SecretEnc != "" {
			plain, err := cipher.Decrypt(wh.SecretEnc, "webhooks:secret_enc")
			if err != nil {
				return nil, fmt.Errorf("decrypt webhooks(%d) secret: %w", wh.ID, err)
			}
			addSecret(plain)
		}
	}

	return secrets, nil
}

func extractArchiveSafely(r io.Reader, stageDir string, maxCompressed int64) (map[string]string, error) {
	limitedUpload := &limitedCountReader{r: r, remaining: maxCompressed}
	gz, err := gzip.NewReader(limitedUpload)
	if err != nil {
		if limitedUpload.exceeded {
			return nil, &ValidationError{Message: "backup archive exceeds maximum allowed upload size"}
		}
		return nil, &ValidationError{Message: "invalid gzip backup archive", Cause: err}
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	hashes := make(map[string]string)
	var totalUncompressed int64
	entryCount := 0

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if limitedUpload.exceeded {
				return nil, &ValidationError{Message: "backup archive exceeds maximum allowed upload size"}
			}
			return nil, &ValidationError{Message: "corrupted tar stream", Cause: err}
		}

		entryCount++
		if entryCount > maxArchiveEntries {
			return nil, &ValidationError{Message: "backup archive contains too many entries"}
		}

		// Strictly allow only regular files and directories; reject symlinks, hardlinks, devices, FIFOs.
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir {
			return nil, &ValidationError{Message: fmt.Sprintf("forbidden tar entry type %q for %q (symlinks/links/special files are not allowed)", hdr.Typeflag, hdr.Name)}
		}

		isDir := hdr.Typeflag == tar.TypeDir
		cleaned, err := sanitizeArchivePath(hdr.Name, isDir)
		if err != nil {
			return nil, err
		}
		if isDir && cleaned == "." {
			continue
		}

		targetPath := filepath.Join(stageDir, filepath.FromSlash(cleaned))
		relCheck, relErr := filepath.Rel(stageDir, targetPath)
		if relErr != nil || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(filepath.Separator)) {
			return nil, &ValidationError{Message: fmt.Sprintf("tar-slip path detected: %q", hdr.Name)}
		}

		if isDir {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return nil, fmt.Errorf("create staged directory %q: %w", cleaned, err)
			}
			continue
		}

		if hdr.Size < 0 || totalUncompressed+hdr.Size > maxUncompressedBytes {
			return nil, &ValidationError{Message: "backup archive uncompressed content exceeds size limit"}
		}
		if _, exists := hashes[cleaned]; exists {
			return nil, &ValidationError{Message: fmt.Sprintf("duplicate archive entry %q", cleaned)}
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return nil, fmt.Errorf("create parent dir for %q: %w", cleaned, err)
		}

		f, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create staged file %q: %w", cleaned, err)
		}

		h := sha256.New()
		mw := io.MultiWriter(f, h)
		n, copyErr := io.Copy(mw, io.LimitReader(tr, hdr.Size+1))
		closeErr := f.Close()
		if copyErr != nil {
			return nil, &ValidationError{Message: fmt.Sprintf("read archive entry %q", cleaned), Cause: copyErr}
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close staged file %q: %w", cleaned, closeErr)
		}
		if n != hdr.Size {
			return nil, &ValidationError{Message: fmt.Sprintf("archive entry %q size mismatch", cleaned)}
		}
		totalUncompressed += n
		if totalUncompressed > maxUncompressedBytes {
			return nil, &ValidationError{Message: "backup archive uncompressed content exceeds size limit"}
		}

		hashes[cleaned] = hex.EncodeToString(h.Sum(nil))
	}

	if limitedUpload.exceeded {
		return nil, &ValidationError{Message: "backup archive exceeds maximum allowed upload size"}
	}

	return hashes, nil
}

func sanitizeArchivePath(raw string, isDir bool) (string, error) {
	if raw == "" || strings.ContainsRune(raw, '\x00') || strings.ContainsRune(raw, '\\') {
		return "", &ValidationError{Message: fmt.Sprintf("invalid archive entry path %q", raw)}
	}
	if strings.HasPrefix(raw, "/") {
		return "", &ValidationError{Message: fmt.Sprintf("absolute path not allowed in archive: %q", raw)}
	}
	if strings.Contains(raw, "..") {
		for _, seg := range strings.Split(strings.TrimSuffix(raw, "/"), "/") {
			if seg == ".." {
				return "", &ValidationError{Message: fmt.Sprintf("path traversal not allowed in archive: %q", raw)}
			}
		}
	}

	cleaned := path.Clean(raw)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") {
		return "", &ValidationError{Message: fmt.Sprintf("path traversal not allowed in archive: %q", raw)}
	}
	if cleaned == "." {
		if !isDir {
			return "", &ValidationError{Message: fmt.Sprintf("invalid file path %q", raw)}
		}
		return ".", nil
	}
	return cleaned, nil
}

func validateCandidateSQLite(ctx context.Context, candDBPath string, candCipher *crypto.Cipher) error {
	dsn := fmt.Sprintf("file:%s?mode=ro", filepath.ToSlash(candDBPath))
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return &ValidationError{Message: "failed to open candidate app.db", Cause: err}
	}
	defer func() { _ = sqlDB.Close() }()

	var integrity string
	if err := sqlDB.QueryRowContext(ctx, "PRAGMA integrity_check;").Scan(&integrity); err != nil {
		return &ValidationError{Message: "candidate app.db integrity_check failed", Cause: err}
	}
	if strings.ToLower(strings.TrimSpace(integrity)) != "ok" {
		return &ValidationError{Message: fmt.Sprintf("candidate app.db integrity_check returned %q", integrity)}
	}

	rows, err := sqlDB.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return &ValidationError{Message: "failed to inspect candidate app.db schema", Cause: err}
	}
	var gotTables []string
	for rows.Next() {
		var name string
		if scanErr := rows.Scan(&name); scanErr != nil {
			_ = rows.Close()
			return &ValidationError{Message: "failed to read candidate app.db tables", Cause: scanErr}
		}
		gotTables = append(gotTables, name)
	}
	_ = rows.Close()

	if len(gotTables) != len(expectedTables) {
		return &ValidationError{Message: fmt.Sprintf("candidate app.db has %d tables, expected %d", len(gotTables), len(expectedTables))}
	}
	for i := range expectedTables {
		if gotTables[i] != expectedTables[i] {
			return &ValidationError{Message: fmt.Sprintf("candidate app.db schema mismatch: got %v, want %v", gotTables, expectedTables)}
		}
	}

	// Test-decrypt encrypted rows across all encrypted columns to verify master.key matches app.db.
	if err := testDecryptColumn(ctx, sqlDB, candCipher, "ca_accounts", "acme_key_enc"); err != nil {
		return err
	}
	if err := testDecryptColumn(ctx, sqlDB, candCipher, "dns_credentials", "config_enc"); err != nil {
		return err
	}
	if err := testDecryptColumn(ctx, sqlDB, candCipher, "hosts", "ssh_private_key_enc"); err != nil {
		return err
	}
	if err := testDecryptColumn(ctx, sqlDB, candCipher, "hosts", "ssh_passphrase_enc"); err != nil {
		return err
	}
	if err := testDecryptColumn(ctx, sqlDB, candCipher, "hosts", "ssh_password_enc"); err != nil {
		return err
	}
	if err := testDecryptColumn(ctx, sqlDB, candCipher, "webhooks", "headers_enc"); err != nil {
		return err
	}
	if err := testDecryptColumn(ctx, sqlDB, candCipher, "webhooks", "secret_enc"); err != nil {
		return err
	}

	return nil
}

func testDecryptColumn(ctx context.Context, sqlDB *sql.DB, candCipher *crypto.Cipher, table, col string) error {
	aad := table + ":" + col
	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s != ''", col, table, col)
	rows, err := sqlDB.QueryContext(ctx, query)
	if err != nil {
		return &ValidationError{Message: fmt.Sprintf("failed to query %s", aad), Cause: err}
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var enc string
		if err := rows.Scan(&enc); err != nil {
			return &ValidationError{Message: fmt.Sprintf("failed to scan %s", aad), Cause: err}
		}
		if enc == "" {
			continue
		}
		if _, err := candCipher.Decrypt(enc, aad); err != nil {
			return &ValidationError{Message: fmt.Sprintf("master.key cannot decrypt %s", aad), Cause: err}
		}
	}
	return rows.Err()
}

type limitedCountReader struct {
	r         io.Reader
	remaining int64
	exceeded  bool
}

func (l *limitedCountReader) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		var probe [1]byte
		n, err := l.r.Read(probe[:])
		if n > 0 {
			l.exceeded = true
			return 0, errors.New("upload size limit exceeded")
		}
		return 0, err
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	return n, err
}

func hashAndSizeFile(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func copyFileWithMode(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func installFileAtomic(src, dst string, mode os.FileMode) error {
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".restore-file-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		_ = tmp.Close()
		return err
	}
	_, copyErr := io.Copy(tmp, in)
	_ = in.Close()
	if copyErr != nil {
		_ = tmp.Close()
		return copyErr
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func moveDir(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := copyDir(src, dst); err != nil {
		return err
	}
	return os.RemoveAll(src)
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return copyFileWithMode(p, target, info.Mode().Perm())
	})
}
