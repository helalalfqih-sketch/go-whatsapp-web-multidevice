package oauth

import (
	"context"
	"fmt"
	"html/template"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
)

const (
	qrLinkTTL               = 4 * time.Minute
	maxOAuthWhatsAppDevices = 10
)

type pendingWhatsAppLink struct {
	Request         authorizationRequest
	Client          Client
	DeviceID        string
	QRBase64        string
	LinkedDeviceIDs []string
	ExpiresAt       time.Time
}

type linkState struct {
	mu      sync.Mutex
	pending map[string]*pendingWhatsAppLink
}

func newLinkState() *linkState {
	return &linkState{pending: make(map[string]*pendingWhatsAppLink)}
}

type linkPageData struct {
	ClientName    string
	DeviceID      string
	QRBase64      string
	Ticket        string
	CompletePath  string
	LinkedCount   int
	MaxDevices    int
	CanAddAnother bool
	Error         string
}

var whatsappLinkTemplate = template.Must(template.New("oauth-whatsapp-link").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Link WhatsApp</title>
  <style>body{font-family:system-ui,sans-serif;max-width:30rem;margin:3rem auto;padding:0 1rem;text-align:center}img{width:min(360px,92vw);height:auto;border:1px solid #ddd;border-radius:12px;padding:.5rem}button{margin-top:1.25rem;padding:.8rem 1.1rem;font:inherit;font-weight:700}.error{color:#a00}.muted{color:#666;font-size:.9rem}</style>
</head>
<body>
  <h1>Link WhatsApp</h1>
  <p>Open WhatsApp on your phone → Settings → Linked devices → Link a device, then scan this QR code.</p>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <img src="data:image/png;base64,{{.QRBase64}}" alt="WhatsApp linking QR code">
  <p class="muted">{{.LinkedCount}} account(s) already linked in this sign-in.</p>
  <form method="post" action="{{.CompletePath}}">
    <input type="hidden" name="ticket" value="{{.Ticket}}">
    <input type="hidden" name="action" value="complete">
    <button type="submit">I scanned the QR — continue to ChatGPT</button>
  </form>
  {{if .CanAddAnother}}
  <form method="post" action="{{.CompletePath}}">
    <input type="hidden" name="ticket" value="{{.Ticket}}">
    <input type="hidden" name="action" value="add">
    <button type="submit">I scanned the QR — add another WhatsApp account</button>
  </form>
  {{end}}
  <p class="muted">This OAuth connection will be restricted to the WhatsApp accounts linked during this sign-in. Maximum {{.MaxDevices}} accounts.</p>
</body>
</html>`))

func (s *Server) startWhatsAppLink(c fiber.Ctx, req authorizationRequest, client Client) error {
	// Fiber/fasthttp body-bound strings may alias the request buffer, which is
	// reused after this handler returns. Clone every persisted string before
	// storing authorization state across the QR follow-up requests.
	req = cloneAuthorizationRequest(req)
	client = cloneOAuthClient(client)

	if s.linker == nil || s.links == nil {
		return oauthError(c, fiber.StatusServiceUnavailable, "temporarily_unavailable", "WhatsApp QR linking is not configured")
	}

	link, err := s.linker.Start(c.Context())
	if err != nil {
		return oauthError(c, fiber.StatusBadGateway, "temporarily_unavailable", "could not start WhatsApp QR linking")
	}
	if strings.TrimSpace(link.DeviceID) == "" || strings.TrimSpace(link.QRBase64) == "" {
		_ = s.linker.Cleanup(context.Background(), link.DeviceID)
		return oauthError(c, fiber.StatusBadGateway, "temporarily_unavailable", "WhatsApp QR linking returned incomplete data")
	}

	ticket, err := randomSecret("gowa_link_", 32)
	if err != nil {
		_ = s.linker.Cleanup(context.Background(), link.DeviceID)
		return oauthError(c, fiber.StatusInternalServerError, "server_error", "could not create WhatsApp link ticket")
	}
	expiresAt := s.now().Add(qrLinkTTL)
	s.links.mu.Lock()
	s.links.pending[ticket] = &pendingWhatsAppLink{
		Request:   req,
		Client:    client,
		DeviceID:  link.DeviceID,
		QRBase64:  link.QRBase64,
		ExpiresAt: expiresAt,
	}
	s.links.mu.Unlock()

	go s.expireWhatsAppLink(ticket, link.DeviceID, expiresAt)
	return s.renderWhatsAppLink(c, fiber.StatusOK, ticket, s.links.pendingSnapshot(ticket), "")
}

func (s *Server) pendingLink(ticket string) (*pendingWhatsAppLink, bool) {
	if s.links == nil {
		return nil, false
	}
	s.links.mu.Lock()
	defer s.links.mu.Unlock()
	pending, ok := s.links.pending[ticket]
	if !ok || pending == nil {
		return nil, false
	}
	copy := *pending
	return &copy, true
}

func (s *linkState) pendingSnapshot(ticket string) *pendingWhatsAppLink {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := s.pending[ticket]
	if pending == nil {
		return nil
	}
	copy := *pending
	return &copy
}

func (s *Server) expireWhatsAppLink(ticket, deviceID string, expiresAt time.Time) {
	wait := time.Until(expiresAt)
	if wait > 0 {
		time.Sleep(wait)
	}
	if s.links == nil {
		return
	}
	s.links.mu.Lock()
	pending, ok := s.links.pending[ticket]
	expired := ok && pending != nil && !s.now().Before(pending.ExpiresAt)
	if expired {
		delete(s.links.pending, ticket)
	}
	s.links.mu.Unlock()
	if expired && s.linker != nil {
		for _, linkedDeviceID := range pending.LinkedDeviceIDs {
			_ = s.linker.Cleanup(context.Background(), linkedDeviceID)
		}
		_ = s.linker.Cleanup(context.Background(), deviceID)
	}
}

func (s *Server) completeWhatsAppLink(c fiber.Ctx) error {
	s.setNoStore(c)
	var body struct {
		Ticket string `form:"ticket"`
		Action string `form:"action"`
	}
	if err := c.Bind().Body(&body); err != nil || strings.TrimSpace(body.Ticket) == "" {
		return oauthError(c, fiber.StatusBadRequest, "invalid_request", "invalid WhatsApp link ticket")
	}
	ticket := strings.TrimSpace(body.Ticket)
	action := strings.TrimSpace(body.Action)
	if action == "" {
		action = "complete"
	}
	if action != "complete" && action != "add" {
		return oauthError(c, fiber.StatusBadRequest, "invalid_request", "invalid WhatsApp link action")
	}

	if s.links == nil || s.linker == nil {
		return oauthError(c, fiber.StatusServiceUnavailable, "temporarily_unavailable", "WhatsApp QR linking is not configured")
	}

	s.links.mu.Lock()
	pending, ok := s.links.pending[ticket]
	if !ok || pending == nil {
		s.links.mu.Unlock()
		return oauthError(c, fiber.StatusBadRequest, "invalid_request", "WhatsApp link ticket is invalid or expired")
	}
	if !s.now().Before(pending.ExpiresAt) {
		deviceID := pending.DeviceID
		linkedDeviceIDs := append([]string(nil), pending.LinkedDeviceIDs...)
		delete(s.links.pending, ticket)
		s.links.mu.Unlock()
		for _, linkedDeviceID := range linkedDeviceIDs {
			_ = s.linker.Cleanup(context.Background(), linkedDeviceID)
		}
		_ = s.linker.Cleanup(context.Background(), deviceID)
		return oauthError(c, fiber.StatusBadRequest, "invalid_request", "WhatsApp link ticket expired; restart the connection")
	}

	linked, err := s.linker.IsLinked(c.Context(), pending.DeviceID)
	if err != nil {
		copy := *pending
		s.links.mu.Unlock()
		return s.renderWhatsAppLink(c, fiber.StatusBadGateway, ticket, &copy, "Could not verify the WhatsApp connection. Try again.")
	}
	if !linked {
		copy := *pending
		s.links.mu.Unlock()
		return s.renderWhatsAppLink(c, fiber.StatusConflict, ticket, &copy, "WhatsApp is not linked yet. Scan the QR code first, then continue.")
	}

	req := pending.Request
	deviceIDs := append([]string(nil), pending.LinkedDeviceIDs...)
	if !containsDeviceID(deviceIDs, pending.DeviceID) {
		deviceIDs = append(deviceIDs, pending.DeviceID)
	}

	if action == "add" {
		if len(deviceIDs) >= maxOAuthWhatsAppDevices {
			copy := *pending
			copy.LinkedDeviceIDs = deviceIDs
			s.links.mu.Unlock()
			return s.renderWhatsAppLink(c, fiber.StatusBadRequest, ticket, &copy, "Maximum WhatsApp accounts reached for this connection.")
		}

		nextLink, err := s.linker.Start(c.Context())
		if err != nil {
			copy := *pending
			copy.LinkedDeviceIDs = deviceIDs
			s.links.mu.Unlock()
			return s.renderWhatsAppLink(c, fiber.StatusBadGateway, ticket, &copy, "Could not start another WhatsApp link. You can continue with the accounts already linked.")
		}
		if strings.TrimSpace(nextLink.DeviceID) == "" || strings.TrimSpace(nextLink.QRBase64) == "" {
			_ = s.linker.Cleanup(context.Background(), nextLink.DeviceID)
			copy := *pending
			copy.LinkedDeviceIDs = deviceIDs
			s.links.mu.Unlock()
			return s.renderWhatsAppLink(c, fiber.StatusBadGateway, ticket, &copy, "Could not start another WhatsApp link. You can continue with the accounts already linked.")
		}

		nextTicket, err := randomSecret("gowa_link_", 32)
		if err != nil {
			_ = s.linker.Cleanup(context.Background(), nextLink.DeviceID)
			copy := *pending
			copy.LinkedDeviceIDs = deviceIDs
			s.links.mu.Unlock()
			return s.renderWhatsAppLink(c, fiber.StatusInternalServerError, ticket, &copy, "Could not create another WhatsApp link ticket.")
		}
		expiresAt := s.now().Add(qrLinkTTL)
		delete(s.links.pending, ticket)
		s.links.pending[nextTicket] = &pendingWhatsAppLink{
			Request:         req,
			Client:          pending.Client,
			DeviceID:        nextLink.DeviceID,
			QRBase64:        nextLink.QRBase64,
			LinkedDeviceIDs: deviceIDs,
			ExpiresAt:       expiresAt,
		}
		nextPending := *s.links.pending[nextTicket]
		s.links.mu.Unlock()

		go s.expireWhatsAppLink(nextTicket, nextLink.DeviceID, expiresAt)
		return s.renderWhatsAppLink(c, fiber.StatusOK, nextTicket, &nextPending, "")
	}

	code, err := s.store.issueAuthorizationCode(c.Context(), AuthorizationGrant{
		ClientID:      req.ClientID,
		Subject:       DevicesSubject(deviceIDs),
		RedirectURI:   req.RedirectURI,
		CodeChallenge: req.CodeChallenge,
		Resource:      req.Resource,
		Scope:         req.Scope,
	}, s.now(), codeTTL)
	if err != nil {
		s.links.mu.Unlock()
		return oauthError(c, fiber.StatusInternalServerError, "server_error", "could not issue authorization code")
	}
	delete(s.links.pending, ticket)
	s.links.mu.Unlock()

	redirectURL, err := url.Parse(req.RedirectURI)
	if err != nil {
		return oauthError(c, fiber.StatusBadRequest, "invalid_request", "redirect_uri is not a valid URI")
	}
	query := redirectURL.Query()
	query.Set("code", code)
	if req.State != "" {
		query.Set("state", req.State)
	}
	query.Set("iss", s.issuer.String())
	redirectURL.RawQuery = query.Encode()
	s.setNoStore(c)
	return c.Redirect().Status(fiber.StatusFound).To(redirectURL.String())
}

func (s *Server) renderWhatsAppLink(c fiber.Ctx, status int, ticket string, pending *pendingWhatsAppLink, pageError string) error {
	if pending == nil {
		return oauthError(c, fiber.StatusBadRequest, "invalid_request", "WhatsApp link ticket is invalid or expired")
	}
	s.setNoStore(c)
	c.Set(fiber.HeaderContentSecurityPolicy, whatsappLinkPageCSP(pending.Request.RedirectURI))
	c.Set(fiber.HeaderXFrameOptions, "DENY")
	c.Set(fiber.HeaderReferrerPolicy, "no-referrer")
	c.Type("html", "utf-8")
	c.Status(status)
	return whatsappLinkTemplate.Execute(c, linkPageData{
		ClientName:    pending.Client.Name,
		DeviceID:      pending.DeviceID,
		QRBase64:      pending.QRBase64,
		Ticket:        ticket,
		CompletePath:  s.issuerEndpointPath("/oauth/link/complete"),
		LinkedCount:   len(pending.LinkedDeviceIDs),
		MaxDevices:    maxOAuthWhatsAppDevices,
		CanAddAnother: len(pending.LinkedDeviceIDs)+1 < maxOAuthWhatsAppDevices,
		Error:         pageError,
	})
}

func whatsappLinkPageCSP(redirectURI string) string {
	formAction := "'self'"
	if origin := redirectOrigin(redirectURI); origin != "" {
		formAction += " " + origin
	}
	return fmt.Sprintf("default-src 'none'; img-src data:; style-src 'unsafe-inline'; form-action %s; frame-ancestors 'none'; base-uri 'none'", formAction)
}

func containsDeviceID(deviceIDs []string, deviceID string) bool {
	deviceID = strings.TrimSpace(deviceID)
	for _, id := range deviceIDs {
		if strings.TrimSpace(id) == deviceID && deviceID != "" {
			return true
		}
	}
	return false
}


func cloneAuthorizationRequest(req authorizationRequest) authorizationRequest {
	return authorizationRequest{
		ResponseType:        strings.Clone(req.ResponseType),
		ClientID:            strings.Clone(req.ClientID),
		RedirectURI:         strings.Clone(req.RedirectURI),
		CodeChallenge:       strings.Clone(req.CodeChallenge),
		CodeChallengeMethod: strings.Clone(req.CodeChallengeMethod),
		Resource:            strings.Clone(req.Resource),
		Scope:               strings.Clone(req.Scope),
		State:               strings.Clone(req.State),
		Username:            strings.Clone(req.Username),
		Password:            strings.Clone(req.Password),
	}
}

func cloneOAuthClient(client Client) Client {
	redirects := make([]string, len(client.RedirectURIs))
	for i, redirectURI := range client.RedirectURIs {
		redirects[i] = strings.Clone(redirectURI)
	}
	return Client{
		ID:                      strings.Clone(client.ID),
		Name:                    strings.Clone(client.Name),
		RedirectURIs:            redirects,
		ApplicationType:         strings.Clone(client.ApplicationType),
		TokenEndpointAuthMethod: strings.Clone(client.TokenEndpointAuthMethod),
		CreatedAt:               client.CreatedAt,
	}
}
