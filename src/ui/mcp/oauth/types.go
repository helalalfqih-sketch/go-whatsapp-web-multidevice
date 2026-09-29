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

const deviceSubjectPrefix = "whatsapp-device:"

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

func DeviceIDFromSubject(subject string) (string, bool) {
	if !strings.HasPrefix(subject, deviceSubjectPrefix) {
		return "", false
	}
	deviceID := strings.TrimSpace(strings.TrimPrefix(subject, deviceSubjectPrefix))
	return deviceID, deviceID != ""
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
