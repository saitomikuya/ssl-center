package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"ssl-center/internal/backup"
	"ssl-center/internal/config"
)

// BackupHandler serves /api/v1/backup/export and /api/v1/backup/restore.
type BackupHandler struct {
	svc *backup.Service
	cfg *config.Config
}

// NewBackupHandler constructs a BackupHandler.
func NewBackupHandler(svc *backup.Service, cfg *config.Config) *BackupHandler {
	return &BackupHandler{
		svc: svc,
		cfg: cfg,
	}
}

// Export handles POST /api/v1/backup/export.
func (h *BackupHandler) Export(w http.ResponseWriter, r *http.Request) {
	if err := os.MkdirAll(h.cfg.TmpDir(), 0o700); err != nil {
		Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to prepare export temp directory", nil)
		return
	}

	tmpFile, err := os.CreateTemp(h.cfg.TmpDir(), "export-stream-*.tar.gz")
	if err != nil {
		Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to create export temp file", nil)
		return
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	if err := h.svc.ExportBackup(r.Context(), tmpFile); err != nil {
		Fail(w, http.StatusInternalServerError, CodeInternalError, "Backup export failed: "+err.Error(), nil)
		return
	}
	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to rewind export archive", nil)
		return
	}
	stat, err := tmpFile.Stat()
	if err != nil {
		Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to stat export archive", nil)
		return
	}

	filename := fmt.Sprintf("ssl-center-backup-%s.tar.gz", time.Now().UTC().Format("20060102T150405Z"))
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, tmpFile)
}

// Restore handles POST /api/v1/backup/restore (multipart form field "file").
func (h *BackupHandler) Restore(w http.ResponseWriter, r *http.Request) {
	const multipartOverhead = 2 << 20
	r.Body = http.MaxBytesReader(w, r.Body, backup.DefaultMaxBackupBytes+multipartOverhead)

	mr, err := r.MultipartReader()
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Expected multipart/form-data upload with 'file' field", nil)
		return
	}

	var fileReader io.ReadCloser
	for {
		part, partErr := mr.NextPart()
		if errors.Is(partErr, io.EOF) {
			break
		}
		if partErr != nil {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "Failed to read multipart upload: "+partErr.Error(), nil)
			return
		}
		if part.FormName() == "file" {
			fileReader = part
			break
		}
		_ = part.Close()
	}

	if fileReader == nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Missing 'file' form field in multipart upload", nil)
		return
	}
	defer func() { _ = fileReader.Close() }()

	res, err := h.svc.RestoreBackup(r.Context(), fileReader, backup.DefaultMaxBackupBytes, ClientIPFromContext(r.Context()))
	if err != nil {
		var ve *backup.ValidationError
		switch {
		case errors.As(err, &ve):
			Fail(w, http.StatusBadRequest, CodeBadRequest, ve.Error(), nil)
		case strings.Contains(err.Error(), "maintenance operation already in progress"):
			Fail(w, http.StatusServiceUnavailable, CodeMaintenanceInProgress, "Maintenance operation already in progress", nil)
		default:
			Fail(w, http.StatusInternalServerError, CodeInternalError, "Backup restore failed: "+err.Error(), nil)
		}
		return
	}

	OK(w, res)
}
