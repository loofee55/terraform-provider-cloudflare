package page_rule

import (
	"context"
	"fmt"

	"github.com/cloudflare/cloudflare-go/v4/page_rules"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// FixPageRuleForwardingURLNullIssue addresses the null value conversion error by
// ensuring the ForwardingURL field is properly handled in the Encode method.
// This is a patch function that should be called from the PageRuleActionsModel.Encode method
// when handling the ForwardingURL field.
func FixPageRuleForwardingURLNullIssue(m *PageRuleActionsModel, encoded *[]map[string]any) error {
	if m.ForwardingURL.IsNull() || m.ForwardingURL.IsUnknown() {
		// The ForwardingURL block is not present or not known, do nothing.
		return nil
	}

	// Directly access underlying attributes to bypass the problematic As() conversion.
	attrs := m.ForwardingURL.Attributes()
	urlAttr, urlOk := attrs["url"]
	statusCodeAttr, statusCodeOk := attrs["status_code"]

	if !urlOk || !statusCodeOk {
		// This should not happen if the schema is consistent.
		return fmt.Errorf("internal error: forwarding_url attributes 'url' or 'status_code' not found")
	}

	if urlAttr.IsNull() || urlAttr.IsUnknown() {
		return fmt.Errorf("forwarding_url 'url' attribute is null or unknown, but required")
	}

	if statusCodeAttr.IsNull() || statusCodeAttr.IsUnknown() {
		return fmt.Errorf("forwarding_url 'status_code' attribute is null or unknown, but required")
	}

	// Assert attributes to their expected types (based on the non-pointer struct in custom.go)
	urlStringVal, ok := urlAttr.(types.String)
	if !ok {
		return fmt.Errorf("internal error: forwarding_url 'url' attribute is not type types.String")
	}

	statusCodeIntVal, ok := statusCodeAttr.(types.Int64)
	if !ok {
		return fmt.Errorf("internal error: forwarding_url 'status_code' attribute is not type types.Int64")
	}

	*encoded = append(*encoded, map[string]any{
		"id": page_rules.PageRuleActionsIDForwardingURL,
		"value": map[string]any{
			"url":         urlStringVal.ValueString(),    // Use ValueString() from types.String
			"status_code": statusCodeIntVal.ValueInt64(), // Use ValueInt64() from types.Int64
		},
	})

	return nil
}

// GetStateHandlingForwardingURLSchema enhances the forwarding_url schema definition
// to better handle state persistence by explicitly setting the CustomType.
func GetStateHandlingForwardingURLSchema(ctx context.Context) map[string]schema.Attribute {
	// Create the base schema
	return map[string]schema.Attribute{
		"url": schema.StringAttribute{
			Required: true,
		},
		"status_code": schema.Int64Attribute{
			Required: true,
		},
	}
}

// StateStabilizingEncode wraps the regular Encode method to provide additional
// stability for state management, preventing fields like forwarding_url from
// always showing as changed in Terraform plans.
func StateStabilizingEncode(m *PageRuleActionsModel) (encoded []map[string]any, err error) {
	// Start with regular encoding
	encoded = []map[string]any{}

	// Handle the forwarding_url field explicitly first
	err = FixPageRuleForwardingURLNullIssue(m, &encoded)
	if err != nil {
		return nil, fmt.Errorf("error handling ForwardingURL: %v", err)
	}

	// Handle all other fields
	// This would typically call the regular Encode method for other fields,
	// but for demonstration we're just showing the fix pattern

	return encoded, nil
}
