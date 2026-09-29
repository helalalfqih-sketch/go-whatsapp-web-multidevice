package mcp

import (
	"context"
	"errors"
	"strings"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/infrastructure/whatsapp"
	mcpg "github.com/mark3labs/mcp-go/mcp"
)

// deviceResolver is the subset of *whatsapp.DeviceManager the MCP layer needs.
type deviceResolver interface {
	ResolveDevice(deviceID string) (*whatsapp.DeviceInstance, string, error)
}

// resolveDeviceContext returns a context carrying the device a tool call acts
// on. Priority: explicit device_id argument > device injected by the HTTP
// layer from the X-Device-Id header (see route.go) > error. Mirrors REST's
// DeviceMiddleware semantics for MCP handlers.
func resolveDeviceContext(ctx context.Context, request mcpg.CallToolRequest, resolver deviceResolver) (context.Context, *whatsapp.DeviceInstance, error) {
	requestedDeviceID := strings.TrimSpace(request.GetString("device_id", ""))

	if allowedDeviceIDs, ok := oauthAllowedDevices(ctx); ok {
		deviceID := requestedDeviceID
		if deviceID == "" {
			if len(allowedDeviceIDs) == 1 {
				deviceID = allowedDeviceIDs[0]
			} else if inst, hasContextDevice := whatsapp.DeviceFromContext(ctx); hasContextDevice && inst != nil {
				deviceID = inst.ID()
			} else {
				return ctx, nil, errors.New("multiple WhatsApp accounts are linked to this OAuth connection; pass device_id to choose an account")
			}
		}
		if !containsAllowedDevice(allowedDeviceIDs, deviceID) {
			return ctx, nil, errors.New("device_id is not authorized for this OAuth connection")
		}
		if resolver == nil {
			return ctx, nil, errors.New("device manager not initialized")
		}
		inst, _, err := resolver.ResolveDevice(deviceID)
		if err != nil {
			return ctx, nil, err
		}
		return whatsapp.ContextWithDevice(ctx, inst), inst, nil
	}

	if deviceID := requestedDeviceID; deviceID != "" {
		if resolver == nil {
			return ctx, nil, errors.New("device manager not initialized")
		}
		inst, _, err := resolver.ResolveDevice(deviceID)
		if err != nil {
			return ctx, nil, err
		}
		return whatsapp.ContextWithDevice(ctx, inst), inst, nil
	}
	if inst, ok := whatsapp.DeviceFromContext(ctx); ok && inst != nil {
		return ctx, inst, nil
	}
	return ctx, nil, errors.New("device identification required: set the X-Device-Id header or pass device_id")
}

func containsAllowedDevice(deviceIDs []string, deviceID string) bool {
	deviceID = strings.TrimSpace(deviceID)
	for _, allowed := range deviceIDs {
		if strings.TrimSpace(allowed) == deviceID && deviceID != "" {
			return true
		}
	}
	return false
}
