package oauth

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalidGrant      = errors.New("invalid grant")
	ErrInvalidTarget     = errors.New("invalid target")
	ErrInvalidToken      = errors.New("invalid token")
	ErrRefreshReuse      = errors.New("refresh token reuse detected")
	ErrRegistrationLimit = errors.New("dynamic client registration limit reached")
)

type CredentialValidator func(username, password string) bool

const (
	deviceSubjectPrefix  = "whatsapp-device:"
	devicesSubjectPrefix = "whatsapp-devices:"
	AllowedDevicesHeader = "X-OAuth-Allowed-Device-Ids"
)

type WhatsAppLink struct {
	DeviceID string
	QRBase64 string
}

type WhatsAppLinker interface {
	Start(ctx context.Context) (WhatsAppLink, error)
	IsLinked(ctx context.Context, deviceID string) (bool, error)
	Cleanup(ctx context.Context, deviceID string) error
}

func DeviceSubject(deviceID string) string {
	return deviceSubjectPrefix + strings.TrimSpace(deviceID)
}

func DevicesSubject(deviceIDs []string) string {
	seen := make(map[string]struct{}, len(deviceIDs))
	clean := make([]string, 0, len(deviceIDs))
	for _, id := range deviceIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		clean = append(clean, id)
	}
	if len(clean) == 1 {
		return DeviceSubject(clean[0])
	}
	return devicesSubjectPrefix + strings.Join(clean, ",")
}

func DeviceIDsFromSubject(subject string) ([]string, bool) {
	if strings.HasPrefix(subject, deviceSubjectPrefix) {
		deviceID := strings.TrimSpace(strings.TrimPrefix(subject, deviceSubjectPrefix))
		if deviceID == "" {
			return nil, false
		}
		return []string{deviceID}, true
	}
	if !strings.HasPrefix(subject, devicesSubjectPrefix) {
		return nil, false
	}
	raw := strings.TrimSpace(strings.TrimPrefix(subject, devicesSubjectPrefix))
	if raw == "" {
		return nil, false
	}
	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{}, len(parts))
	devices := make([]string, 0, len(parts))
	for _, part := range parts {
		id := strings.TrimSpace(part)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		devices = append(devices, id)
	}
	return devices, len(devices) > 0
}

func DeviceIDFromSubject(subject string) (string, bool) {
	devices, ok := DeviceIDsFromSubject(subject)
	if !ok || len(devices) != 1 {
		return "", false
	}
	return devices[0], true
}

type Config struct {
	IssuerURL   string
	ResourceURL string
	StorageURI  string
	QRLinking   bool
	Linker      WhatsAppLinker
}

type Client struct {
	ID                      string
	Name                    string
	RedirectURIs            []string
	ApplicationType         string
	TokenEndpointAuthMethod string
	CreatedAt               time.Time
}

type AuthorizationGrant struct {
	ClientID      string
	Subject       string
	RedirectURI   string
	CodeChallenge string
	Resource      string
	Scope         string
}

type CodeExchange struct {
	ClientID     string
	Code         string
	RedirectURI  string
	CodeVerifier string
	Resource     string
}

type RefreshExchange struct {
	ClientID     string
	RefreshToken string
	Resource     string
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	Scope        string
}

type Principal struct {
	Subject  string
	ClientID string
	Scope    string
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}
