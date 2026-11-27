package crypto

import (
	"bytes"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const (
	// RedactedPlaceholder replaces masked secrets in logs and command outputs.
	RedactedPlaceholder = "***REDACTED***"
	// MinSecretLen prevents short strings from causing false-positive log redaction.
	MinSecretLen = 6
	// MinPEMLineLen prevents trivial PEM headers/footers or short trailing lines from false-positive matching.
	MinPEMLineLen = 12
	// maxRedactingBufferBytes bounds buffered data for unclosed PEM blocks.
	maxRedactingBufferBytes = 64 * 1024
)

var pemPrivKeyRegex = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

// SecretRedactor dynamically tracks active plaintext secrets with reference counting
// and masks them in logs, SSE streams, and command outputs.
type SecretRedactor struct {
	mu               sync.RWMutex
	counts           map[string]int
	replacer         *strings.Replacer
	maxSecretLen     int
	maxLineSecretLen int
}

// NewSecretRedactor creates an empty thread-safe SecretRedactor.
func NewSecretRedactor() *SecretRedactor {
	return &SecretRedactor{
		counts: make(map[string]int),
	}
}

// Add registers one or more secrets (and constituent base64 lines for multi-line PEM keys)
// with reference counting. Secrets shorter than MinSecretLen (6 chars) or substrings of
// RedactedPlaceholder are ignored.
func (r *SecretRedactor) Add(secrets ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range secrets {
		r.addLocked(s)
	}
	r.rebuildLocked()
}

// Remove decrements the reference count for one or more secrets and their derived PEM lines,
// deleting a token only when its count reaches zero.
func (r *SecretRedactor) Remove(secrets ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range secrets {
		r.removeLocked(s)
	}
	r.rebuildLocked()
}

// ReplaceAll atomically replaces the entire registered secret set.
func (r *SecretRedactor) ReplaceAll(secrets []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counts = make(map[string]int, len(secrets))
	for _, s := range secrets {
		r.addLocked(s)
	}
	r.rebuildLocked()
}

// Redact replaces all registered secrets in a single longest-first pass and masks any
// PEM private key blocks with RedactedPlaceholder.
func (r *SecretRedactor) Redact(input string) string {
	if input == "" {
		return ""
	}

	r.mu.RLock()
	replacer := r.replacer
	r.mu.RUnlock()

	out := input
	if replacer != nil {
		out = replacer.Replace(out)
	}
	if strings.Contains(out, "PRIVATE KEY-----") {
		out = pemPrivKeyRegex.ReplaceAllString(out, RedactedPlaceholder)
	}
	return out
}

// RedactingWriter wraps w with a streaming writer that buffers a sliding tail window
// so secrets split across Write boundaries are still redacted. Callers should call
// Flush or Close when finished writing to emit any buffered trailing bytes.
func (r *SecretRedactor) RedactingWriter(w io.Writer) *RedactingWriter {
	if w == nil {
		w = io.Discard
	}
	return &RedactingWriter{
		redactor: r,
		dest:     w,
	}
}

func (r *SecretRedactor) tailWindowLen() int {
	r.mu.RLock()
	n := r.maxLineSecretLen
	r.mu.RUnlock()
	if n <= 1 {
		return 0
	}
	return n - 1
}

func (r *SecretRedactor) addLocked(s string) {
	for _, tok := range extractSecretTokens(s) {
		r.counts[tok]++
	}
}

func (r *SecretRedactor) removeLocked(s string) {
	for _, tok := range extractSecretTokens(s) {
		if c, ok := r.counts[tok]; ok {
			if c <= 1 {
				delete(r.counts, tok)
			} else {
				r.counts[tok] = c - 1
			}
		}
	}
}

func extractSecretTokens(s string) []string {
	if len(s) < MinSecretLen {
		return nil
	}
	seen := make(map[string]struct{})
	var tokens []string
	addToken := func(tok string) {
		if len(tok) < MinSecretLen {
			return
		}
		// Never register substrings of "***REDACTED***" (e.g. "REDACTED")
		// so Redact never double-replaces the placeholder.
		if strings.Contains(RedactedPlaceholder, tok) {
			return
		}
		if _, exists := seen[tok]; exists {
			return
		}
		seen[tok] = struct{}{}
		tokens = append(tokens, tok)
	}

	addToken(s)
	normalized := strings.ReplaceAll(s, "\r\n", "\n")
	if normalized != s {
		addToken(normalized)
	}
	if strings.Contains(normalized, "\n") {
		for _, line := range strings.Split(normalized, "\n") {
			trimmed := strings.TrimSpace(line)
			if isTrivialPEMLine(trimmed) {
				continue
			}
			if len(trimmed) >= MinPEMLineLen {
				addToken(trimmed)
			}
		}
	}
	return tokens
}

func (r *SecretRedactor) rebuildLocked() {
	if len(r.counts) == 0 {
		r.replacer = nil
		r.maxSecretLen = 0
		r.maxLineSecretLen = 0
		return
	}

	sorted := make([]string, 0, len(r.counts))
	maxAll := 0
	maxLine := 0
	for s, c := range r.counts {
		if c <= 0 {
			continue
		}
		sorted = append(sorted, s)
		if len(s) > maxAll {
			maxAll = len(s)
		}
		if !strings.Contains(s, "\n") && len(s) > maxLine {
			maxLine = len(s)
		}
	}
	if len(sorted) == 0 {
		r.replacer = nil
		r.maxSecretLen = 0
		r.maxLineSecretLen = 0
		return
	}

	sort.Slice(sorted, func(i, j int) bool {
		if len(sorted[i]) != len(sorted[j]) {
			return len(sorted[i]) > len(sorted[j])
		}
		return sorted[i] < sorted[j]
	})

	pairs := make([]string, 0, len(sorted)*2)
	for _, s := range sorted {
		pairs = append(pairs, s, RedactedPlaceholder)
	}
	r.replacer = strings.NewReplacer(pairs...)
	r.maxSecretLen = maxAll
	r.maxLineSecretLen = maxLine
}

func isTrivialPEMLine(line string) bool {
	return strings.HasPrefix(line, "-----BEGIN ") ||
		strings.HasPrefix(line, "-----END ") ||
		strings.HasPrefix(line, "Proc-Type:") ||
		strings.HasPrefix(line, "DEK-Info:")
}

// RedactingWriter wraps an io.Writer and redacts secrets across Write boundaries.
type RedactingWriter struct {
	redactor *SecretRedactor
	dest     io.Writer
	mu       sync.Mutex
	buf      []byte
}

// Write appends p to the sliding buffer and flushes complete redacted prefixes.
func (rw *RedactingWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	rw.mu.Lock()
	defer rw.mu.Unlock()

	rw.buf = append(rw.buf, p...)

	if !hasUnclosedPEMPrivateKey(rw.buf) || len(rw.buf) >= maxRedactingBufferBytes {
		if lastNL := bytes.LastIndexByte(rw.buf, '\n'); lastNL >= 0 {
			chunk := string(rw.buf[:lastNL+1])
			redacted := rw.redactor.Redact(chunk)
			if _, err := io.WriteString(rw.dest, redacted); err != nil {
				return 0, err
			}
			remaining := copy(rw.buf, rw.buf[lastNL+1:])
			rw.buf = rw.buf[:remaining]
		}

		tailLen := rw.redactor.tailWindowLen()
		if len(rw.buf) > tailLen {
			redacted := rw.redactor.Redact(string(rw.buf))
			if tailLen == 0 {
				if _, err := io.WriteString(rw.dest, redacted); err != nil {
					return 0, err
				}
				rw.buf = rw.buf[:0]
			} else if len(redacted) > tailLen {
				cut := len(redacted) - tailLen
				if _, err := io.WriteString(rw.dest, redacted[:cut]); err != nil {
					return 0, err
				}
				rw.buf = append(rw.buf[:0], redacted[cut:]...)
			} else {
				rw.buf = append(rw.buf[:0], redacted...)
			}
		}
	}

	return len(p), nil
}

// Flush redacts and writes any buffered trailing bytes to the underlying writer.
func (rw *RedactingWriter) Flush() error {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if len(rw.buf) == 0 {
		return nil
	}
	redacted := rw.redactor.Redact(string(rw.buf))
	if _, err := io.WriteString(rw.dest, redacted); err != nil {
		return err
	}
	rw.buf = rw.buf[:0]
	return nil
}

// Close flushes any remaining buffered bytes to the underlying writer without closing it.
func (rw *RedactingWriter) Close() error {
	return rw.Flush()
}

func hasUnclosedPEMPrivateKey(buf []byte) bool {
	idx := bytes.LastIndex(buf, []byte("-----BEGIN "))
	if idx < 0 {
		return false
	}
	tail := buf[idx:]
	nl := bytes.IndexByte(tail, '\n')
	if nl < 0 {
		return bytes.Contains(tail, []byte("PRIVATE")) || len(tail) < 40
	}
	header := tail[:nl]
	if !bytes.Contains(header, []byte("PRIVATE KEY-----")) {
		return false
	}
	return !bytes.Contains(tail[nl:], []byte("-----END "))
}
