package mcp

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/infrastructure/whatsapp"
	mcpg "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.mau.fi/whatsmeow"
	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
)

type catalogProduct struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Description  string            `json:"description,omitempty"`
	RetailerID   string            `json:"retailer_id,omitempty"`
	URL          string            `json:"url,omitempty"`
	Price        int64             `json:"price"`
	Currency     string            `json:"currency,omitempty"`
	IsHidden     bool              `json:"is_hidden"`
	Availability string            `json:"availability"`
	ReviewStatus map[string]string `json:"review_status,omitempty"`
	ImageURLs    map[string]string `json:"image_urls,omitempty"`
}

type catalogCollection struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Status   string           `json:"status,omitempty"`
	CanAppeal bool            `json:"can_appeal"`
	Products []catalogProduct `json:"products"`
}

type catalogPage struct {
	Products       []catalogProduct `json:"products"`
	NextPageCursor string           `json:"next_page_cursor,omitempty"`
}

type CatalogHandler struct {
	resolver deviceResolver
}

func InitMcpCatalog(resolver deviceResolver) *CatalogHandler {
	return &CatalogHandler{resolver: resolver}
}

func (h *CatalogHandler) AddCatalogTools(mcpServer *server.MCPServer) {
	tool := mcpg.NewTool("whatsapp_catalog",
		mcpg.WithDescription("Read the linked WhatsApp Business catalog: list products, fetch one product, or list collections. Read-only."),
		mcpg.WithTitleAnnotation("WhatsApp Business Catalog"),
		mcpg.WithReadOnlyHintAnnotation(true),
		mcpg.WithDestructiveHintAnnotation(false),
		mcpg.WithIdempotentHintAnnotation(true),
		mcpg.WithRawInputSchema([]byte(catalogSchema)),
	)
	tool.InputSchema = mcpg.ToolInputSchema{}
	mcpServer.AddTool(tool, h.handleCatalog)
}

func (h *CatalogHandler) handleCatalog(ctx context.Context, request mcpg.CallToolRequest) (*mcpg.CallToolResult, error) {
	ctx, inst, err := resolveDeviceContext(ctx, request, h.resolver)
	if err != nil {
		return mcpg.NewToolResultError(err.Error()), nil
	}
	client := inst.GetClient()
	if client == nil || client.Store == nil || client.Store.ID == nil || !client.IsLoggedIn() {
		return mcpg.NewToolResultError("WhatsApp device is not logged in"), nil
	}

	action, err := request.RequireString("action")
	if err != nil {
		return mcpg.NewToolResultError(err.Error()), nil
	}
	bizJID := client.Store.ID.ToNonAD()

	switch action {
	case "list_products":
		limit := request.GetInt("limit", 20)
		if limit < 1 {
			limit = 1
		}
		if limit > 100 {
			limit = 100
		}
		cursor := strings.TrimSpace(request.GetString("cursor", ""))
		page, err := fetchCatalogPage(ctx, client, bizJID, limit, cursor)
		if err != nil {
			return mcpg.NewToolResultError(fmt.Sprintf("catalog query failed: %v", err)), nil
		}
		structured := map[string]any{
			"device_id":        inst.ID(),
			"business_jid":     bizJID.String(),
			"products":         page.Products,
			"next_page_cursor": page.NextPageCursor,
		}
		return mcpg.NewToolResultStructured(structured, fmt.Sprintf("returned %d catalog products", len(page.Products))), nil

	case "get_product":
		productID := strings.TrimSpace(request.GetString("product_id", ""))
		retailerID := strings.TrimSpace(request.GetString("retailer_id", ""))
		if productID == "" && retailerID == "" {
			return mcpg.NewToolResultError("product_id or retailer_id is required"), nil
		}
		product, err := findCatalogProduct(ctx, client, bizJID, productID, retailerID)
		if err != nil {
			return mcpg.NewToolResultError(err.Error()), nil
		}
		structured := map[string]any{
			"device_id":    inst.ID(),
			"business_jid": bizJID.String(),
			"product":      product,
		}
		return mcpg.NewToolResultStructured(structured, product.Name), nil

	case "list_collections":
		limit := request.GetInt("limit", 51)
		if limit < 1 {
			limit = 1
		}
		if limit > 100 {
			limit = 100
		}
		collections, err := fetchCatalogCollections(ctx, client, bizJID, limit)
		if err != nil {
			return mcpg.NewToolResultError(fmt.Sprintf("catalog collections query failed: %v", err)), nil
		}
		structured := map[string]any{
			"device_id":    inst.ID(),
			"business_jid": bizJID.String(),
			"collections":  collections,
		}
		return mcpg.NewToolResultStructured(structured, fmt.Sprintf("returned %d catalog collections", len(collections))), nil
	default:
		return mcpg.NewToolResultError(fmt.Sprintf("unknown catalog action: %s", action)), nil
	}
}

func fetchCatalogPage(ctx context.Context, client *whatsmeow.Client, bizJID types.JID, limit int, cursor string) (catalogPage, error) {
	params := []waBinary.Node{
		{Tag: "limit", Attrs: waBinary.Attrs{}, Content: []byte(strconv.Itoa(limit))},
		{Tag: "width", Attrs: waBinary.Attrs{}, Content: []byte("100")},
		{Tag: "height", Attrs: waBinary.Attrs{}, Content: []byte("100")},
	}
	if cursor != "" {
		params = append(params, waBinary.Node{Tag: "after", Attrs: waBinary.Attrs{}, Content: []byte(cursor)})
	}

	resp, err := client.DangerousInternals().SendIQ(ctx, whatsmeow.DangerousInfoQuery{
		Namespace: "w:biz:catalog",
		Type:      whatsmeow.DangerousInfoQueryType("get"),
		To:        types.ServerJID,
		Content: []waBinary.Node{{
			Tag: "product_catalog",
			Attrs: waBinary.Attrs{
				"jid":               bizJID,
				"allow_shop_source": "true",
			},
			Content: params,
		}},
	})
	if err != nil {
		return catalogPage{}, err
	}
	catalogNode, ok := resp.GetOptionalChildByTag("product_catalog")
	if !ok {
		return catalogPage{}, errors.New("product_catalog missing from WhatsApp response")
	}
	out := catalogPage{}
	for _, productNode := range catalogNode.GetChildrenByTag("product") {
		out.Products = append(out.Products, parseCatalogProduct(productNode))
	}
	if paging, ok := catalogNode.GetOptionalChildByTag("paging"); ok {
		out.NextPageCursor = childText(paging, "after")
	}
	return out, nil
}

func fetchCatalogCollections(ctx context.Context, client *whatsmeow.Client, bizJID types.JID, limit int) ([]catalogCollection, error) {
	resp, err := client.DangerousInternals().SendIQ(ctx, whatsmeow.DangerousInfoQuery{
		Namespace: "w:biz:catalog",
		Type:      whatsmeow.DangerousInfoQueryType("get"),
		To:        types.ServerJID,
		SMaxID:    "35",
		Content: []waBinary.Node{{
			Tag:   "collections",
			Attrs: waBinary.Attrs{"biz_jid": bizJID},
			Content: []waBinary.Node{
				{Tag: "collection_limit", Attrs: waBinary.Attrs{}, Content: []byte(strconv.Itoa(limit))},
				{Tag: "item_limit", Attrs: waBinary.Attrs{}, Content: []byte(strconv.Itoa(limit))},
				{Tag: "width", Attrs: waBinary.Attrs{}, Content: []byte("100")},
				{Tag: "height", Attrs: waBinary.Attrs{}, Content: []byte("100")},
			},
		}},
	})
	if err != nil {
		return nil, err
	}
	root, ok := resp.GetOptionalChildByTag("collections")
	if !ok {
		return nil, errors.New("collections missing from WhatsApp response")
	}
	collections := make([]catalogCollection, 0, len(root.GetChildrenByTag("collection")))
	for _, node := range root.GetChildrenByTag("collection") {
		collection := catalogCollection{
			ID:   childText(node, "id"),
			Name: childText(node, "name"),
		}
		if statusNode, ok := node.GetOptionalChildByTag("status_info"); ok {
			collection.Status = childText(statusNode, "status")
			collection.CanAppeal = strings.EqualFold(childText(statusNode, "can_appeal"), "true")
		}
		for _, productNode := range node.GetChildrenByTag("product") {
			collection.Products = append(collection.Products, parseCatalogProduct(productNode))
		}
		collections = append(collections, collection)
	}
	return collections, nil
}

func findCatalogProduct(ctx context.Context, client *whatsmeow.Client, bizJID types.JID, productID, retailerID string) (*catalogProduct, error) {
	cursor := ""
	for pageNumber := 0; pageNumber < 20; pageNumber++ {
		page, err := fetchCatalogPage(ctx, client, bizJID, 100, cursor)
		if err != nil {
			return nil, err
		}
		for i := range page.Products {
			product := &page.Products[i]
			if (productID != "" && product.ID == productID) || (retailerID != "" && product.RetailerID == retailerID) {
				return product, nil
			}
		}
		if page.NextPageCursor == "" || page.NextPageCursor == cursor {
			break
		}
		cursor = page.NextPageCursor
	}
	return nil, errors.New("catalog product not found")
}

func parseCatalogProduct(node waBinary.Node) catalogProduct {
	product := catalogProduct{
		ID:           childText(node, "id"),
		Name:         childText(node, "name"),
		Description:  childText(node, "description"),
		RetailerID:   childText(node, "retailer_id"),
		URL:          childText(node, "url"),
		Currency:     childText(node, "currency"),
		IsHidden:     attrBool(node.Attrs["is_hidden"]),
		Availability: "in stock",
	}
	if rawPrice := childText(node, "price"); rawPrice != "" {
		product.Price, _ = strconv.ParseInt(rawPrice, 10, 64)
	}
	if statusNode, ok := node.GetOptionalChildByTag("status_info"); ok {
		product.ReviewStatus = map[string]string{"whatsapp": childText(statusNode, "status")}
	}
	if mediaNode, ok := node.GetOptionalChildByTag("media"); ok {
		if imageNode, ok := mediaNode.GetOptionalChildByTag("image"); ok {
			product.ImageURLs = map[string]string{}
			if value := childText(imageNode, "request_image_url"); value != "" {
				product.ImageURLs["requested"] = value
			}
			if value := childText(imageNode, "original_image_url"); value != "" {
				product.ImageURLs["original"] = value
			}
		}
	}
	return product
}

func childText(node waBinary.Node, tag string) string {
	child, ok := node.GetOptionalChildByTag(tag)
	if !ok {
		return ""
	}
	switch value := child.Content.(type) {
	case []byte:
		return string(value)
	case string:
		return value
	default:
		return ""
	}
}

func attrBool(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(typed, "true") || typed == "1"
	default:
		return false
	}
}

var _ = whatsapp.ContextWithDevice
