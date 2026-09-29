package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/config"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/pkg/sqlite"
	"github.com/sirupsen/logrus"
)

const (
	stateBackupMagic       = "GOWASTATE1"
	stateBackupMaxBytes    = 70 << 20
	defaultBackupInterval  = 30 * time.Second
	stateRegistryStaging   = "storages/gowa-device-registry.json"
)

type stateGrant struct {
	URL       string `json:"url"`
	ExpiresIn int    `json:"expiresIn"`
}

type deviceRegistryRecord struct {
	DeviceID    string `json:"device_id"`
	DisplayName string `json:"display_name"`
	JID         string `json:"jid"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type stateBackupManager struct {
	gatewayURL string
	basicAuth  string
	key        []byte
	interval   time.Duration
	client     *http.Client

	mu     sync.Mutex
	stopCh chan struct{}
	doneCh chan struct{}
}

func newStateBackupManagerFromEnv() *stateBackupManager {
	gatewayURL := strings.TrimSpace(os.Getenv("GOWA_STATE_GATEWAY_URL"))
	keyRaw := strings.TrimSpace(os.Getenv("GOWA_STATE_ENCRYPTION_KEY"))
	if gatewayURL == "" && keyRaw == "" {
		return nil
	}
	if gatewayURL == "" || keyRaw == "" {
		logrus.Warn("[STATE_BACKUP] disabled: both GOWA_STATE_GATEWAY_URL and GOWA_STATE_ENCRYPTION_KEY are required")
		return nil
	}

	parsed, err := url.Parse(gatewayURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		logrus.Warn("[STATE_BACKUP] disabled: gateway URL must be an HTTPS URL without embedded credentials")
		return nil
	}

	key, err := base64.StdEncoding.DecodeString(keyRaw)
	if err != nil || len(key) != 32 {
		logrus.Warn("[STATE_BACKUP] disabled: encryption key must be base64-encoded 32 bytes")
		return nil
	}

	basicAuth := ""
	if len(config.AppBasicAuthCredential) > 0 {
		basicAuth = strings.TrimSpace(config.AppBasicAuthCredential[0])
	}
	if basicAuth == "" {
		logrus.Warn("[STATE_BACKUP] disabled: APP_BASIC_AUTH is required for the state gateway")
		return nil
	}

	interval := defaultBackupInterval
	if raw := strings.TrimSpace(os.Getenv("GOWA_STATE_BACKUP_INTERVAL")); raw != "" {
		if parsedInterval, err := time.ParseDuration(raw); err == nil && parsedInterval >= 10*time.Second {
			interval = parsedInterval
		}
	}

	return &stateBackupManager{
		gatewayURL: strings.TrimRight(gatewayURL, "/"),
		basicAuth:  basicAuth,
		key:        key,
		interval:   interval,
		client:     &http.Client{Timeout: 25 * time.Second},
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}
}

func (m *stateBackupManager) RestoreIfNeeded(ctx context.Context) {
	if m == nil || localStatePresent() {
		return
	}

	blob, err := m.download(ctx)
	if errors.Is(err, os.ErrNotExist) {
		logrus.Info("[STATE_BACKUP] no remote state found; starting fresh")
		return
	}
	if err != nil {
		logrus.Warnf("[STATE_BACKUP] remote restore skipped: %v", err)
		return
	}

	plain, err := decryptState(blob, m.key)
	if err != nil {
		logrus.Warnf("[STATE_BACKUP] remote state decrypt failed: %v", err)
		return
	}
	if err := restoreStateArchive(plain); err != nil {
		logrus.Warnf("[STATE_BACKUP] remote state restore failed: %v", err)
		return
	}
	logrus.Info("[STATE_BACKUP] restored WhatsApp/OAuth state from persistent storage")
}

func (m *stateBackupManager) RestoreDeviceRegistry(db *sql.DB) {
	if m == nil || db == nil {
		return
	}
	raw, err := os.ReadFile(stateRegistryStaging)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		logrus.Warnf("[STATE_BACKUP] device registry staging read failed: %v", err)
		return
	}

	var records []deviceRegistryRecord
	if err := json.Unmarshal(raw, &records); err != nil {
		logrus.Warnf("[STATE_BACKUP] device registry staging decode failed: %v", err)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		logrus.Warnf("[STATE_BACKUP] device registry restore begin failed: %v", err)
		return
	}
	defer func() { _ = tx.Rollback() }()

	for _, record := range records {
		if strings.TrimSpace(record.DeviceID) == "" {
			continue
		}
		if _, err := tx.Exec(`
INSERT INTO devices (device_id, display_name, jid, created_at, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(device_id) DO UPDATE SET
	display_name = excluded.display_name,
	jid = excluded.jid,
	updated_at = excluded.updated_at
`, record.DeviceID, record.DisplayName, record.JID, record.CreatedAt, record.UpdatedAt); err != nil {
			logrus.Warnf("[STATE_BACKUP] device registry restore failed: %v", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		logrus.Warnf("[STATE_BACKUP] device registry restore commit failed: %v", err)
		return
	}
	_ = os.Remove(stateRegistryStaging)
	logrus.Infof("[STATE_BACKUP] restored %d device registry record(s)", len(records))
}

func (m *stateBackupManager) Start() {
	if m == nil {
		return
	}
	go func() {
		defer close(m.doneCh)
		timer := time.NewTimer(12 * time.Second)
		defer timer.Stop()

		for {
			select {
			case <-timer.C:
				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
				if err := m.Backup(ctx); err != nil {
					logrus.Warnf("[STATE_BACKUP] periodic backup failed: %v", err)
				}
				cancel()
				timer.Reset(m.interval)
			case <-m.stopCh:
				return
			}
		}
	}()
}

func (m *stateBackupManager) StopAndFlush(ctx context.Context) {
	if m == nil {
		return
	}
	select {
	case <-m.stopCh:
	default:
		close(m.stopCh)
	}
	select {
	case <-m.doneCh:
	case <-ctx.Done():
		return
	}
	if err := m.Backup(ctx); err != nil {
		logrus.Warnf("[STATE_BACKUP] final backup failed: %v", err)
	}
}

func (m *stateBackupManager) Backup(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	archive, err := buildStateArchive()
	if err != nil {
		return err
	}
	if len(archive) == 0 {
		return nil
	}
	blob, err := encryptState(archive, m.key)
	if err != nil {
		return err
	}
	if len(blob) > stateBackupMaxBytes {
		return fmt.Errorf("encrypted state exceeds %d bytes", stateBackupMaxBytes)
	}
	if err := m.upload(ctx, blob); err != nil {
		return err
	}
	logrus.Infof("[STATE_BACKUP] persistent snapshot uploaded (%d bytes)", len(blob))
	return nil
}

func (m *stateBackupManager) gatewayRequest(ctx context.Context, method string) (*stateGrant, error) {
	req, err := http.NewRequestWithContext(ctx, method, m.gatewayURL, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(strings.SplitN(m.basicAuth, ":", 2)[0], strings.SplitN(m.basicAuth, ":", 2)[1])
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway returned HTTP %d", resp.StatusCode)
	}
	var grant stateGrant
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<10)).Decode(&grant); err != nil {
		return nil, err
	}
	u, err := url.Parse(grant.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, errors.New("gateway returned invalid signed URL")
	}
	return &grant, nil
}

func (m *stateBackupManager) upload(ctx context.Context, blob []byte) error {
	grant, err := m.gatewayRequest(ctx, http.MethodPost)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, grant.URL, bytes.NewReader(blob))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Cache-Control", "max-age=0")
	req.Header.Set("x-upsert", "true")

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("signed upload returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (m *stateBackupManager) download(ctx context.Context) ([]byte, error) {
	grant, err := m.gatewayRequest(ctx, http.MethodGet)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, grant.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, os.ErrNotExist
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signed download returned HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, stateBackupMaxBytes+1))
}

func buildStateArchive() ([]byte, error) {
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	closeAll := func() error {
		if err := tw.Close(); err != nil {
			return err
		}
		return gz.Close()
	}

	tempDir, err := os.MkdirTemp("", "gowa-state-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	files := []struct {
		name string
		path string
	}{
		{name: "whatsapp.db", path: sqlitePathFromURI(config.DBURI)},
		{name: "oauth.db", path: sqlitePathFromURI(oauthDBURIFromEnv())},
	}

	wrote := false
	for _, item := range files {
		if item.path == "" {
			continue
		}
		if _, err := os.Stat(item.path); err != nil {
			continue
		}
		snapshot := filepath.Join(tempDir, item.name)
		if err := snapshotSQLite(item.path, snapshot); err != nil {
			return nil, fmt.Errorf("snapshot %s: %w", item.name, err)
		}
		if err := addFileToTar(tw, item.name, snapshot); err != nil {
			return nil, err
		}
		wrote = true
	}

	if registry, err := readDeviceRegistry(config.ChatStorageURI); err == nil && len(registry) > 0 {
		raw, err := json.Marshal(registry)
		if err != nil {
			return nil, err
		}
		if err := addBytesToTar(tw, "devices.json", raw); err != nil {
			return nil, err
		}
		wrote = true
	}

	if err := closeAll(); err != nil {
		return nil, err
	}
	if !wrote {
		return nil, nil
	}
	return out.Bytes(), nil
}

func restoreStateArchive(archive []byte) error {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	if err := os.MkdirAll(config.PathStorages, 0o700); err != nil {
		return err
	}

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		switch header.Name {
		case "whatsapp.db":
			if path := sqlitePathFromURI(config.DBURI); path != "" {
				if err := writeRestoredFile(path, tr, header.Size); err != nil {
					return err
				}
			}
		case "oauth.db":
			if path := sqlitePathFromURI(oauthDBURIFromEnv()); path != "" {
				if err := writeRestoredFile(path, tr, header.Size); err != nil {
					return err
				}
			}
		case "devices.json":
			if err := writeRestoredFile(stateRegistryStaging, tr, header.Size); err != nil {
				return err
			}
		}
	}
	return nil
}

func snapshotSQLite(sourcePath, destinationPath string) error {
	connStr := sqlite.FormatChatStorageURI("file:"+sourcePath, true, true)
	db, err := sql.Open(sqlite.DriverName, connStr)
	if err != nil {
		return err
	}
	defer db.Close()
	quoted := strings.ReplaceAll(destinationPath, "'", "''")
	_, err = db.Exec("VACUUM INTO '" + quoted + "'")
	return err
}

func readDeviceRegistry(uri string) ([]deviceRegistryRecord, error) {
	path := sqlitePathFromURI(uri)
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := sql.Open(sqlite.DriverName, sqlite.FormatChatStorageURI("file:"+path, true, true))
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`
SELECT device_id, display_name, jid,
       CAST(created_at AS TEXT), CAST(updated_at AS TEXT)
FROM devices
ORDER BY device_id
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []deviceRegistryRecord
	for rows.Next() {
		var r deviceRegistryRecord
		if err := rows.Scan(&r.DeviceID, &r.DisplayName, &r.JID, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

func encryptState(plain, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := append([]byte(stateBackupMagic), nonce...)
	return gcm.Seal(out, nonce, plain, []byte(stateBackupMagic)), nil
}

func decryptState(blob, key []byte) ([]byte, error) {
	if len(blob) < len(stateBackupMagic) || string(blob[:len(stateBackupMagic)]) != stateBackupMagic {
		return nil, errors.New("invalid state backup header")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	offset := len(stateBackupMagic)
	if len(blob) < offset+gcm.NonceSize() {
		return nil, errors.New("truncated state backup")
	}
	nonce := blob[offset : offset+gcm.NonceSize()]
	ciphertext := blob[offset+gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, []byte(stateBackupMagic))
}

func addFileToTar(tw *tar.Writer, name, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	header := &tar.Header{Name: name, Mode: 0o600, Size: info.Size(), ModTime: time.Now().UTC()}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

func addBytesToTar(tw *tar.Writer, name string, data []byte) error {
	header := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: time.Now().UTC()}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func writeRestoredFile(path string, r io.Reader, size int64) error {
	if size < 0 || size > stateBackupMaxBytes {
		return errors.New("invalid restored file size")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".restore"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.CopyN(f, r, size)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, path)
}

func sqlitePathFromURI(uri string) string {
	uri = strings.TrimSpace(strings.Trim(uri, "\"'"))
	if !strings.HasPrefix(uri, "file:") {
		return ""
	}
	raw := strings.TrimPrefix(uri, "file:")
	if idx := strings.IndexByte(raw, '?'); idx >= 0 {
		raw = raw[:idx]
	}
	raw = strings.TrimPrefix(raw, "//")
	return filepath.Clean(raw)
}

func oauthDBURIFromEnv() string {
	if raw := strings.TrimSpace(os.Getenv("MCP_OAUTH_DB_URI")); raw != "" {
		return raw
	}
	return config.McpOAuthDBURI
}

func localStatePresent() bool {
	for _, path := range []string{
		sqlitePathFromURI(config.DBURI),
		sqlitePathFromURI(oauthDBURIFromEnv()),
	} {
		if path == "" {
			continue
		}
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			return true
		}
	}
	return false
}
