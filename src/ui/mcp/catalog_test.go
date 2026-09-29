package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	waBinary "go.mau.fi/whatsmeow/binary"
)

func TestParseCatalogProduct(t *testing.T) {
	node := waBinary.Node{
		Tag:   "product",
		Attrs: waBinary.Attrs{"is_hidden": "true"},
		Content: []waBinary.Node{
			{Tag: "id", Content: []byte("123")},
			{Tag: "name", Content: []byte("Test Product")},
			{Tag: "description", Content: []byte("Description")},
			{Tag: "retailer_id", Content: []byte("sku-1")},
			{Tag: "price", Content: []byte("43900")},
			{Tag: "currency", Content: []byte("YER")},
			{Tag: "status_info", Content: []waBinary.Node{
				{Tag: "status", Content: []byte("APPROVED")},
			}},
			{Tag: "media", Content: []waBinary.Node{
				{Tag: "image", Content: []waBinary.Node{
					{Tag: "request_image_url", Content: []byte("https://example.com/request.jpg")},
					{Tag: "original_image_url", Content: []byte("https://example.com/original.jpg")},
				}},
			}},
		},
	}

	product := parseCatalogProduct(node)
	require.Equal(t, "123", product.ID)
	assert.Equal(t, "Test Product", product.Name)
	assert.Equal(t, "sku-1", product.RetailerID)
	assert.Equal(t, int64(43900), product.Price)
	assert.Equal(t, "YER", product.Currency)
	assert.True(t, product.IsHidden)
	assert.Equal(t, "APPROVED", product.ReviewStatus["whatsapp"])
	assert.Equal(t, "https://example.com/original.jpg", product.ImageURLs["original"])
}

func TestChildTextHandlesMissingAndBytes(t *testing.T) {
	node := waBinary.Node{Content: []waBinary.Node{{Tag: "name", Content: []byte("Index")}}}
	assert.Equal(t, "Index", childText(node, "name"))
	assert.Equal(t, "", childText(node, "missing"))
}
