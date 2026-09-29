package mcp

import (
	"context"
	"net/http"
	"strings"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/infrastructure/whatsapp"
	mcpoauth "github.com/aldinokemal/go-whatsapp-web-multidevice/ui/mcp/oauth"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/ui/rest/middleware"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"github.com/mark3labs/mcp-go/server"
	"github.com/sirupsen/logrus"
)

// Register mounts the MCP streamable-HTTP endpoint at /mcp on the given
// router (which already carries AppBasePath and the basic-auth middleware).
//
// Device scoping mirrors REST: the X-Device-Id header picks the device for
// the connection (empty resolves the default device, same as
// DeviceMiddleware); a per-call device_id tool argument overrides it (see
// resolveDeviceContext).
type oauthAllowedDevicesKey struct{}

func withOAuthAllowedDevices(ctx context.Context, deviceIDs []string) context.Context {
	clean := make([]string, 0, len(deviceIDs))
	seen := make(map[string]struct{}, len(deviceIDs))
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
	return context.WithValue(ctx, oauthAllowedDevicesKey{}, clean)
}

func oauthAllowedDevices(ctx context.Context) ([]string, bool) {
	deviceIDs, ok := ctx.Value(oauthAllowedDevicesKey{}).([]string)
	if !ok || len(deviceIDs) == 0 {
		return nil, false
	}
	return append([]string(nil), deviceIDs...), true
}

// Backward-compatible helper for existing single-device tests/callers.
func withOAuthBoundDevice(ctx context.Context, deviceID string) context.Context {
	return withOAuthAllowedDevices(ctx, []string{deviceID})
}

func oauthBoundDevice(ctx context.Context) (string, bool) {
	deviceIDs, ok := oauthAllowedDevices(ctx)
	if !ok || len(deviceIDs) != 1 {
		return "", false
	}
	return deviceIDs[0], true
}

func Register(router fiber.Router, dm *whatsapp.DeviceManager, deps Deps) {
	// dm is typed here, but handlers take the deviceResolver interface;
	// a nil *DeviceManager must become a nil interface, not a typed nil.
	var resolver deviceResolver
	if dm != nil {
		resolver = dm
	}

	httpServer := server.NewStreamableHTTPServer(
		NewServer(deps, resolver),
		// Stateless: no server-initiated notifications or subscriptions are
		// used, and it avoids tying a session store to Fiber's shutdown.
		server.WithStateLess(true),
		// No server-initiated notifications are used, so the standalone GET
		// SSE stream is never needed. Without this, a GET reaches mcp-go's
		// "for { select { case <-writeChan: ...; case <-ctx.Done(): } }"
		// loop; ctx there is the *fasthttp.RequestCtx, whose Done() channel
		// only closes on server shutdown (not client disconnect), so the
		// goroutine, the fasthttp body-stream writer, and the connection/FD
		// would all be pinned forever through the fasthttp adaptor.
		server.WithDisableStreaming(true),
		server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			if dm == nil {
				return ctx
			}

			authorization := strings.TrimSpace(r.Header.Get("Authorization"))
			isBearer := false
			if fields := strings.Fields(authorization); len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") {
				isBearer = true
			}

			if isBearer {
				rawAllowed := strings.TrimSpace(r.Header.Get(mcpoauth.AllowedDevicesHeader))
				if rawAllowed != "" {
					allowed := strings.Split(rawAllowed, ",")
					ctx = withOAuthAllowedDevices(ctx, allowed)

					deviceID := strings.TrimSpace(r.Header.Get(middleware.DeviceIDHeader))
					if deviceID == "" && len(allowed) == 1 {
						deviceID = strings.TrimSpace(allowed[0])
					}
					if deviceID == "" {
						// Multi-account token with no transport-level selection.
						// Tool-level device_id will resolve the intended account.
						return ctx
					}
					inst, _, err := dm.ResolveDevice(deviceID)
					if err != nil {
						logrus.Debugf("MCP OAuth device resolution failed for %q: %v", deviceID, err)
						return ctx
					}
					return whatsapp.ContextWithDevice(ctx, inst)
				}
			}

			deviceID := strings.TrimSpace(r.Header.Get(middleware.DeviceIDHeader))
			inst, _, err := dm.ResolveDevice(deviceID)
			if err != nil {
				// Leave the context empty; handlers surface a tool error
				// ("device identification required") on use.
				logrus.Debugf("MCP device resolution failed for %q: %v", deviceID, err)
				return ctx
			}
			return whatsapp.ContextWithDevice(ctx, inst)
		}),
	)

	handler := adaptor.HTTPHandler(httpServer)
	// POST carries JSON-RPC calls; DELETE is part of the streamable-HTTP
	// session lifecycle. GET is intentionally not mounted: with streaming
	// disabled mcp-go would just 405 it, so Fiber's own 404 for an
	// unmounted method is equivalent and keeps the route surface narrow.
	router.Post("/mcp", handler)
	router.Delete("/mcp", handler)
}
