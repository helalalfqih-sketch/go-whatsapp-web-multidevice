package cmd

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/config"
	domainApp "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/app"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/infrastructure/whatsapp"
	uimcp "github.com/aldinokemal/go-whatsapp-web-multidevice/ui/mcp"
	mcpoauth "github.com/aldinokemal/go-whatsapp-web-multidevice/ui/mcp/oauth"
	"github.com/gofiber/fiber/v3"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.PersistentFlags().BoolVar(
		&config.McpOAuthEnabled,
		"mcp-oauth-enabled",
		config.McpOAuthEnabled,
		"enable OAuth 2.1 for the MCP endpoint",
	)
	rootCmd.PersistentFlags().StringVar(
		&config.McpOAuthIssuerURL,
		"mcp-oauth-issuer-url",
		config.McpOAuthIssuerURL,
		"public HTTPS OAuth issuer URL, e.g. https://gowa.example.com",
	)
	rootCmd.PersistentFlags().StringVar(
		&config.McpOAuthResourceURL,
		"mcp-oauth-resource-url",
		config.McpOAuthResourceURL,
		"canonical public MCP resource URL; defaults to issuer origin + APP_BASE_PATH + /mcp",
	)
	rootCmd.PersistentFlags().StringVar(
		&config.McpOAuthDBURI,
		"mcp-oauth-db-uri",
		config.McpOAuthDBURI,
		"SQLite or PostgreSQL URI for OAuth clients, authorization codes, and tokens",
	)
	rootCmd.PersistentFlags().BoolVar(
		&config.McpOAuthQRLinking,
		"mcp-oauth-qr-linking",
		config.McpOAuthQRLinking,
		"bind OAuth authorization to one or more WhatsApp linked-device sessions via QR",
	)
}

// loadMcpOAuthEnvConfig runs from restServer after Cobra has parsed flags. It
// mirrors root.go's Viper binding while preserving the project's flag > env >
// .env priority for the OAuth settings added in this feature.
func loadMcpOAuthEnvConfig() {
	flags := rootCmd.PersistentFlags()
	if flag := flags.Lookup("mcp-oauth-enabled"); flag == nil || !flag.Changed {
		if viper.IsSet("mcp_oauth_enabled") {
			config.McpOAuthEnabled = viper.GetBool("mcp_oauth_enabled")
		}
	}
	if flag := flags.Lookup("mcp-oauth-issuer-url"); flag == nil || !flag.Changed {
		if value := strings.TrimSpace(viper.GetString("mcp_oauth_issuer_url")); value != "" {
			config.McpOAuthIssuerURL = value
		}
	}
	if flag := flags.Lookup("mcp-oauth-resource-url"); flag == nil || !flag.Changed {
		if value := strings.TrimSpace(viper.GetString("mcp_oauth_resource_url")); value != "" {
			config.McpOAuthResourceURL = value
		}
	}
	if flag := flags.Lookup("mcp-oauth-db-uri"); flag == nil || !flag.Changed {
		if value := strings.TrimSpace(viper.GetString("mcp_oauth_db_uri")); value != "" {
			config.McpOAuthDBURI = value
		}
	}
	if flag := flags.Lookup("mcp-oauth-qr-linking"); flag == nil || !flag.Changed {
		if viper.IsSet("mcp_oauth_qr_linking") {
			config.McpOAuthQRLinking = viper.GetBool("mcp_oauth_qr_linking")
		}
	}
}

// registerMcpOAuth must run before the application's global Basic Auth
// middleware is installed so standards discovery, authorization, registration,
// and token endpoints remain reachable by OAuth clients.
func registerMcpOAuth(app *fiber.App, dm *whatsapp.DeviceManager) (*mcpoauth.Server, bool, error) {
	if !config.McpEnabled || !config.McpOAuthEnabled {
		return nil, false, nil
	}

	validateCredential, err := mcpOAuthCredentialValidator(config.AppBasicAuthCredential)
	if err != nil {
		return nil, false, err
	}

	resourceURL := strings.TrimSpace(config.McpOAuthResourceURL)
	if resourceURL == "" {
		resourceURL, err = mcpoauth.DefaultResourceURL(config.McpOAuthIssuerURL, config.AppBasePath)
		if err != nil {
			return nil, false, err
		}
	}

	var linker mcpoauth.WhatsAppLinker
	if config.McpOAuthQRLinking {
		linker = &mcpOAuthWhatsAppLinker{dm: dm, app: appUsecase}
	}

	oauthServer, err := mcpoauth.New(mcpoauth.Config{
		IssuerURL:   config.McpOAuthIssuerURL,
		ResourceURL: resourceURL,
		StorageURI:  config.McpOAuthDBURI,
		QRLinking:   config.McpOAuthQRLinking,
		Linker:      linker,
	}, validateCredential)
	if err != nil {
		return nil, false, err
	}

	oauthServer.RegisterPublic(app)

	var mcpRouter fiber.Router = app
	if config.AppBasePath != "" {
		mcpRouter = app.Group(config.AppBasePath)
	}
	useMcpOAuthMiddleware(mcpRouter, oauthServer.MCPAuthMiddleware(validateCredential))
	uimcp.Register(mcpRouter, dm, uimcp.Deps{
		App:      appUsecase,
		Send:     sendUsecase,
		Schedule: scheduleUsecase,
		Chat:     chatUsecase,
		User:     userUsecase,
		Message:  messageUsecase,
		Group:    groupUsecase,
	})

	return oauthServer, true, nil
}

// useMcpOAuthMiddleware limits the OAuth-or-Basic challenge to the MCP
// transport. Mounting it on an empty-prefix group also intercepts unrelated
// REST/UI routes registered later and replaces their normal Basic challenge.
func useMcpOAuthMiddleware(router fiber.Router, auth fiber.Handler) {
	router.Use("/mcp", auth)
}

func mcpOAuthCredentialValidator(credentials []string) (mcpoauth.CredentialValidator, error) {
	if len(credentials) == 0 {
		return nil, errors.New("MCP OAuth requires APP_BASIC_AUTH credentials")
	}
	accounts := make(map[string]string, len(credentials))
	for _, credential := range credentials {
		parts := strings.Split(credential, ":")
		if len(parts) != 2 || parts[0] == "" {
			return nil, fmt.Errorf("basic auth is not valid, use <user>:<secret>")
		}
		accounts[parts[0]] = parts[1]
	}
	return func(username, password string) bool {
		expected, ok := accounts[username]
		if !ok {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(password), []byte(expected)) == 1
	}, nil
}


type mcpOAuthWhatsAppLinker struct {
	dm  *whatsapp.DeviceManager
	app domainApp.IAppUsecase
}

func (l *mcpOAuthWhatsAppLinker) Start(ctx context.Context) (mcpoauth.WhatsAppLink, error) {
	if l == nil || l.dm == nil || l.app == nil {
		return mcpoauth.WhatsAppLink{}, errors.New("WhatsApp linker is not initialized")
	}
	inst, err := l.dm.CreateDevice(ctx, "")
	if err != nil {
		return mcpoauth.WhatsAppLink{}, err
	}
	cleanup := func() {
		_ = l.dm.PurgeDevice(context.Background(), inst.ID())
	}

	resp, err := l.app.Login(ctx, inst.ID())
	if err != nil {
		cleanup()
		return mcpoauth.WhatsAppLink{}, err
	}
	qrBytes, err := os.ReadFile(resp.ImagePath)
	if err != nil {
		cleanup()
		return mcpoauth.WhatsAppLink{}, fmt.Errorf("read WhatsApp QR image: %w", err)
	}
	return mcpoauth.WhatsAppLink{
		DeviceID: inst.ID(),
		QRBase64: base64.StdEncoding.EncodeToString(qrBytes),
	}, nil
}

func (l *mcpOAuthWhatsAppLinker) Refresh(ctx context.Context, deviceID string) (mcpoauth.WhatsAppLink, error) {
	if l == nil || l.app == nil || strings.TrimSpace(deviceID) == "" {
		return mcpoauth.WhatsAppLink{}, errors.New("WhatsApp linker is not initialized")
	}
	resp, err := l.app.Login(ctx, deviceID)
	if err != nil {
		return mcpoauth.WhatsAppLink{}, err
	}
	qrBytes, err := os.ReadFile(resp.ImagePath)
	if err != nil {
		return mcpoauth.WhatsAppLink{}, fmt.Errorf("read refreshed WhatsApp QR image: %w", err)
	}
	return mcpoauth.WhatsAppLink{
		DeviceID: deviceID,
		QRBase64: base64.StdEncoding.EncodeToString(qrBytes),
	}, nil
}

func (l *mcpOAuthWhatsAppLinker) IsLinked(ctx context.Context, deviceID string) (bool, error) {
	if l == nil || l.app == nil {
		return false, errors.New("WhatsApp linker is not initialized")
	}
	_, loggedIn, err := l.app.Status(ctx, deviceID)
	return loggedIn, err
}

func (l *mcpOAuthWhatsAppLinker) Cleanup(ctx context.Context, deviceID string) error {
	if l == nil || l.dm == nil || strings.TrimSpace(deviceID) == "" {
		return nil
	}
	return l.dm.PurgeDevice(ctx, deviceID)
}
