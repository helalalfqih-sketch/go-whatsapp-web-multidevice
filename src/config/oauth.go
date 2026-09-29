package config

var (
	// MCP OAuth is opt-in. When enabled, the REST process embeds an OAuth 2.1
	// authorization server for the MCP endpoint while keeping Basic Auth as a
	// backward-compatible MCP authentication method.
	McpOAuthEnabled     = false
	McpOAuthIssuerURL   = ""
	McpOAuthResourceURL = ""
	McpOAuthDBURI       = "file:storages/oauth.db"
	// When enabled, OAuth authorization binds the resulting token to one WhatsApp
	// linked-device session after a QR scan. Basic Auth still gates starting the flow.
	McpOAuthQRLinking    = false
)
