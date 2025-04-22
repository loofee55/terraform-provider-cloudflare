package page_rule

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cloudflare/cloudflare-go/v4/page_rules"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/apijson"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/customfield"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

func (m PageRuleModel) marshalCustom() (data []byte, err error) {
	if data, err = apijson.MarshalRoot(m); err != nil {
		return
	}
	if data, err = m.marshalTargetsAndActions(data); err != nil {
		return
	}
	return
}

func (m PageRuleModel) marshalCustomForUpdate(state PageRuleModel) (data []byte, err error) {
	if data, err = apijson.MarshalForUpdate(m, state); err != nil {
		return
	}
	if data, err = m.marshalTargetsAndActions(data); err != nil {
		return
	}
	return
}

func (m PageRuleModel) marshalTargetsAndActions(b []byte) (data []byte, err error) {
	var T struct {
		ID         string `json:"id,omitempty"`
		ZoneID     string `json:"zone_id,omitempty"`
		Priority   int64  `json:"priority,omitempty"`
		Status     string `json:"status,omitempty"`
		CreatedOn  string `json:"created_on,omitempty"`
		ModifiedOn string `json:"modified_on,omitempty"`
		Target     string `json:"target,omitempty"`
		Targets    []any  `json:"targets,omitempty"`
		Actions    any    `json:"actions,omitempty"`
	}
	if err = json.Unmarshal(b, &T); err != nil {
		return nil, err
	}

	T.Targets = []any{
		map[string]any{
			"target": "url",
			"constraint": map[string]any{
				"operator": "matches",
				"value":    T.Target,
			},
		},
	}
	T.Target = "" // omitempty

	T.Actions, err = m.Actions.Encode()
	if err != nil {
		return nil, err
	}

	return json.Marshal(T)
}

type PageRuleActionsCacheKeyFieldsQueryStringModel struct {
	Include []types.String `tfsdk:"include" json:"include,computed_optional,omitempty"`
	Exclude []types.String `tfsdk:"exclude" json:"exclude,computed_optional,omitempty"`
}

type PageRuleActionsCacheKeyFieldsHeaderModel struct {
	CheckPresence []types.String `tfsdk:"check_presence" json:"check_presence,computed_optional,omitempty"`
	Include       []types.String `tfsdk:"include" json:"include,computed_optional,omitempty"`
	Exclude       []types.String `tfsdk:"exclude" json:"exclude,computed_optional,omitempty"`
}

type PageRuleActionsCacheKeyFieldsHostModel struct {
	Resolved types.Bool `tfsdk:"resolved" json:"resolved,optional"`
}

type PageRuleActionsCacheKeyFieldsCookieModel struct {
	Include       []types.String `tfsdk:"include" json:"include,computed_optional,omitempty"`
	CheckPresence []types.String `tfsdk:"check_presence" json:"check_presence,computed_optional,omitempty"`
}

type PageRuleActionsCacheKeyFieldsUserModel struct {
	DeviceType types.Bool `tfsdk:"device_type" json:"device_type,optional"`
	Geo        types.Bool `tfsdk:"geo" json:"geo,optional"`
	Lang       types.Bool `tfsdk:"lang" json:"lang,optional"`
}

type PageRuleActionsCacheKeyFieldsModel struct {
	QueryString customfield.NestedObject[PageRuleActionsCacheKeyFieldsQueryStringModel] `tfsdk:"query_string" json:"query_string,optional"`
	Header      customfield.NestedObject[PageRuleActionsCacheKeyFieldsHeaderModel]      `tfsdk:"header" json:"header,optional"`
	Host        customfield.NestedObject[PageRuleActionsCacheKeyFieldsHostModel]        `tfsdk:"host" json:"host,optional"`
	Cookie      customfield.NestedObject[PageRuleActionsCacheKeyFieldsCookieModel]      `tfsdk:"cookie" json:"cookie,optional"`
	User        customfield.NestedObject[PageRuleActionsCacheKeyFieldsUserModel]        `tfsdk:"user" json:"user,optional"`
}

type PageRuleActionsForwardingURLModel struct {
	URL        types.String `tfsdk:"url" json:"url,required"`
	StatusCode types.Int64  `tfsdk:"status_code" json:"status_code,required"`
}

type PageRuleActionsModel struct {
	AlwaysUseHTTPS          types.Bool                                                   `tfsdk:"always_use_https" json:"always_use_https,optional"`
	AutomaticHTTPSRewrites  types.String                                                 `tfsdk:"automatic_https_rewrites" json:"automatic_https_rewrites,optional"`
	BrowserCacheTTL         types.Int64                                                  `tfsdk:"browser_cache_ttl" json:"browser_cache_ttl,optional"`
	BrowserCheck            types.String                                                 `tfsdk:"browser_check" json:"browser_check,optional"`
	BypassCacheOnCookie     types.String                                                 `tfsdk:"bypass_cache_on_cookie" json:"bypass_cache_on_cookie,optional"`
	CacheByDeviceType       types.String                                                 `tfsdk:"cache_by_device_type" json:"cache_by_device_type,optional"`
	CacheDeceptionArmor     types.String                                                 `tfsdk:"cache_deception_armor" json:"cache_deception_armor,optional"`
	CacheLevel              types.String                                                 `tfsdk:"cache_level" json:"cache_level,optional"`
	CacheOnCookie           types.String                                                 `tfsdk:"cache_on_cookie" json:"cache_on_cookie,optional"`
	CacheKeyFields          customfield.NestedObject[PageRuleActionsCacheKeyFieldsModel] `tfsdk:"cache_key_fields" json:"cache_key_fields,optional"`
	CacheTTLByStatus        types.Dynamic                                                `tfsdk:"cache_ttl_by_status" json:"cache_ttl_by_status,optional"`
	DisableApps             types.Bool                                                   `tfsdk:"disable_apps" json:"disable_apps,optional"`
	DisablePerformance      types.Bool                                                   `tfsdk:"disable_performance" json:"disable_performance,optional"`
	DisableSecurity         types.Bool                                                   `tfsdk:"disable_security" json:"disable_security,optional"`
	DisableZaraz            types.Bool                                                   `tfsdk:"disable_zaraz" json:"disable_zaraz,optional"`
	EdgeCacheTTL            types.Int64                                                  `tfsdk:"edge_cache_ttl" json:"edge_cache_ttl,optional"`
	EmailObfuscation        types.String                                                 `tfsdk:"email_obfuscation" json:"email_obfuscation,optional"`
	ExplicitCacheControl    types.String                                                 `tfsdk:"explicit_cache_control" json:"explicit_cache_control,optional"`
	ForwardingURL           customfield.NestedObject[PageRuleActionsForwardingURLModel]  `tfsdk:"forwarding_url" json:"forwarding_url,optional"`
	HostHeaderOverride      types.String                                                 `tfsdk:"host_header_override" json:"host_header_override,optional"`
	IPGeolocation           types.String                                                 `tfsdk:"ip_geolocation" json:"ip_geolocation,optional"`
	Mirage                  types.String                                                 `tfsdk:"mirage" json:"mirage,optional"`
	OpportunisticEncryption types.String                                                 `tfsdk:"opportunistic_encryption" json:"opportunistic_encryption,optional"`
	OriginErrorPagePassThru types.String                                                 `tfsdk:"origin_error_page_pass_thru" json:"origin_error_page_pass_thru,optional"`
	Polish                  types.String                                                 `tfsdk:"polish" json:"polish,optional"`
	ResolveOverride         types.String                                                 `tfsdk:"resolve_override" json:"resolve_override,optional"`
	RespectStrongEtag       types.String                                                 `tfsdk:"respect_strong_etag" json:"respect_strong_etag,optional"`
	ResponseBuffering       types.String                                                 `tfsdk:"response_buffering" json:"response_buffering,optional"`
	RocketLoader            types.String                                                 `tfsdk:"rocket_loader" json:"rocket_loader,optional"`
	SSL                     types.String                                                 `tfsdk:"ssl" json:"ssl,optional"`
	SecurityLevel           types.String                                                 `tfsdk:"security_level" json:"security_level,optional"`
	SortQueryStringForCache types.String                                                 `tfsdk:"sort_query_string_for_cache" json:"sort_query_string_for_cache,optional"`
	TrueClientIPHeader      types.String                                                 `tfsdk:"true_client_ip_header" json:"true_client_ip_header,optional"`
	WAF                     types.String                                                 `tfsdk:"waf" json:"waf,optional"`
}

func (m *PageRuleActionsModel) Encode() (encoded []map[string]any, err error) {
	encoded = []map[string]any{}
	if m.AlwaysUseHTTPS.ValueBool() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDAlwaysUseHTTPS})
	}
	if !m.AutomaticHTTPSRewrites.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDAutomaticHTTPSRewrites, "value": m.AutomaticHTTPSRewrites.String()})
	}
	if !m.BrowserCacheTTL.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDBrowserCacheTTL, "value": m.BrowserCacheTTL.ValueInt64()})
	}
	if !m.BrowserCheck.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDBrowserCheck, "value": m.BrowserCheck.ValueString()})
	}
	if !m.BypassCacheOnCookie.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDBypassCacheOnCookie, "value": m.BypassCacheOnCookie.ValueString()})
	}
	if !m.CacheByDeviceType.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDCacheByDeviceType, "value": m.CacheByDeviceType.ValueString()})
	}
	if !m.CacheDeceptionArmor.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDCacheDeceptionArmor, "value": m.CacheDeceptionArmor.ValueString()})
	}
	if !m.CacheLevel.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDCacheLevel, "value": m.CacheLevel.ValueString()})
	}
	if !m.CacheOnCookie.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDCacheOnCookie, "value": m.CacheOnCookie.ValueString()})
	}
	if !m.CacheKeyFields.IsNull() {
		var ckf PageRuleActionsCacheKeyFieldsModel
		m.CacheKeyFields.As(context.TODO(), &ckf, basetypes.ObjectAsOptions{})

		var host PageRuleActionsCacheKeyFieldsHostModel
		ckf.Host.As(context.TODO(), &host, basetypes.ObjectAsOptions{})

		var user PageRuleActionsCacheKeyFieldsUserModel
		ckf.User.As(context.TODO(), &user, basetypes.ObjectAsOptions{})

		var qs PageRuleActionsCacheKeyFieldsQueryStringModel
		ckf.QueryString.As(context.TODO(), &qs, basetypes.ObjectAsOptions{})

		var header PageRuleActionsCacheKeyFieldsHeaderModel
		ckf.Header.As(context.TODO(), &header, basetypes.ObjectAsOptions{})

		var cookie PageRuleActionsCacheKeyFieldsCookieModel
		ckf.Cookie.As(context.TODO(), &cookie, basetypes.ObjectAsOptions{})

		encoded = append(encoded, map[string]any{
			"id": page_rules.PageRuleActionsIDCacheKeyFields,
			"value": map[string]any{
				"cookie": map[string][]string{
					"include":        convertToStringSlice(cookie.Include),
					"check_presence": convertToStringSlice(cookie.CheckPresence),
				},
				"header": map[string][]string{
					"include":        convertToStringSlice(header.Include),
					"exclude":        convertToStringSlice(header.Exclude),
					"check_presence": convertToStringSlice(header.CheckPresence),
				},
				"host": map[string]bool{
					"resolved": host.Resolved.ValueBool(),
				},
				"query_string": map[string][]string{
					"include": convertToStringSlice(qs.Include),
					"exclude": convertToStringSlice(qs.Exclude),
				},
				"user": map[string]bool{
					"geo":         user.Geo.ValueBool(),
					"device_type": user.DeviceType.ValueBool(),
					"lang":        user.Lang.ValueBool(),
				},
			},
		})
	}
	if !m.CacheTTLByStatus.IsNull() {
		stringVal := m.CacheTTLByStatus.String()
		ttl := map[string]interface{}{}

		json.Unmarshal([]byte(stringVal), &ttl)
		value := map[string]any{}
		for k, v := range ttl {
			value[k] = v
		}

		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDCacheTTLByStatus, "value": value})
	}
	if m.DisableApps.ValueBool() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDDisableApps, "value": m.DisableApps.ValueBool()})
	}
	if m.DisablePerformance.ValueBool() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDDisablePerformance})
	}
	if m.DisableSecurity.ValueBool() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDDisableSecurity})
	}
	if m.DisableZaraz.ValueBool() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDDisableZaraz})
	}
	if !m.EdgeCacheTTL.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDEdgeCacheTTL, "value": m.EdgeCacheTTL.ValueInt64()})
	}
	if !m.EmailObfuscation.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDEmailObfuscation, "value": m.EmailObfuscation.ValueString()})
	}
	if !m.ExplicitCacheControl.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDExplicitCacheControl, "value": m.ExplicitCacheControl.ValueString()})
	}

	// Use the stabilized ForwardingURL handling with proper error handling
	err = FixPageRuleForwardingURLNullIssue(m, &encoded)
	if err != nil {
		// We use fmt.Errorf to wrap the returned error which could be from diagnostics
		// This ensures consistent error handling and avoids potential nil panics
		return nil, fmt.Errorf("error handling ForwardingURL: %v", err)
	}

	if !m.HostHeaderOverride.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDHostHeaderOverride, "value": m.HostHeaderOverride.ValueString()})
	}
	if !m.IPGeolocation.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDIPGeolocation, "value": m.IPGeolocation.ValueString()})
	}

	if !m.Mirage.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDMirage, "value": m.Mirage.ValueString()})
	}
	if !m.OpportunisticEncryption.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDOpportunisticEncryption, "value": m.OpportunisticEncryption.ValueString()})
	}
	if !m.OriginErrorPagePassThru.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDOriginErrorPagePassThru, "value": m.OriginErrorPagePassThru.ValueString()})
	}
	if !m.Polish.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDPolish, "value": m.Polish.ValueString()})
	}
	if !m.ResolveOverride.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDResolveOverride, "value": m.ResolveOverride.ValueString()})
	}
	if !m.RespectStrongEtag.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDRespectStrongEtag, "value": m.RespectStrongEtag.ValueString()})
	}
	if !m.ResponseBuffering.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDResponseBuffering, "value": m.ResponseBuffering.ValueString()})
	}
	if !m.RocketLoader.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDRocketLoader, "value": m.RocketLoader.ValueString()})
	}
	if !m.SecurityLevel.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDSecurityLevel, "value": m.SecurityLevel.ValueString()})
	}
	if !m.SortQueryStringForCache.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDSortQueryStringForCache, "value": m.SortQueryStringForCache.ValueString()})
	}
	if !m.SSL.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDSSL, "value": m.SSL.ValueString()})
	}
	if !m.TrueClientIPHeader.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDTrueClientIPHeader, "value": m.TrueClientIPHeader.ValueString()})
	}
	if !m.WAF.IsNull() {
		encoded = append(encoded, map[string]any{"id": page_rules.PageRuleActionsIDWAF, "value": m.WAF.ValueString()})
	}

	return
}

// Decode populates the PageRuleActionsModel fields from the API's actions list format.
func (m *PageRuleActionsModel) Decode(ctx context.Context, actions []apiActionValue) diag.Diagnostics {
	var diags diag.Diagnostics
	// Initialize all fields to null/default initially to clear previous state
	*m = PageRuleActionsModel{}

	for _, action := range actions {
		tflog.Debug(ctx, "Decoding action from API", map[string]interface{}{"id": action.ID, "value": action.Value})
		switch action.ID {
		case string(page_rules.PageRuleActionsIDAlwaysUseHTTPS):
			m.AlwaysUseHTTPS = types.BoolValue(true)
		case string(page_rules.PageRuleActionsIDAutomaticHTTPSRewrites):
			if v, ok := action.Value.(string); ok {
				m.AutomaticHTTPSRewrites = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for automatic_https_rewrites", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDBrowserCacheTTL):
			if v, ok := action.Value.(float64); ok { // JSON numbers often unmarshal as float64
				m.BrowserCacheTTL = types.Int64Value(int64(v))
			} else {
				diags.AddWarning("Invalid type for browser_cache_ttl", fmt.Sprintf("Expected number, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDBrowserCheck):
			if v, ok := action.Value.(string); ok {
				m.BrowserCheck = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for browser_check", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDBypassCacheOnCookie):
			if v, ok := action.Value.(string); ok {
				m.BypassCacheOnCookie = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for bypass_cache_on_cookie", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDCacheByDeviceType):
			if v, ok := action.Value.(string); ok {
				m.CacheByDeviceType = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for cache_by_device_type", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDCacheDeceptionArmor):
			if v, ok := action.Value.(string); ok {
				m.CacheDeceptionArmor = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for cache_deception_armor", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDCacheLevel):
			if v, ok := action.Value.(string); ok {
				m.CacheLevel = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for cache_level", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDCacheOnCookie):
			if v, ok := action.Value.(string); ok {
				m.CacheOnCookie = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for cache_on_cookie", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDDisableApps):
			// Note: API represents this as just {"id": "disable_apps"}, no value usually.
			// Presence implies true.
			m.DisableApps = types.BoolValue(true)
		case string(page_rules.PageRuleActionsIDDisablePerformance):
			m.DisablePerformance = types.BoolValue(true)
		case string(page_rules.PageRuleActionsIDDisableSecurity):
			m.DisableSecurity = types.BoolValue(true)
		case string(page_rules.PageRuleActionsIDDisableZaraz):
			m.DisableZaraz = types.BoolValue(true)
		case string(page_rules.PageRuleActionsIDEdgeCacheTTL):
			if v, ok := action.Value.(float64); ok { // JSON numbers often unmarshal as float64
				m.EdgeCacheTTL = types.Int64Value(int64(v))
			} else {
				diags.AddWarning("Invalid type for edge_cache_ttl", fmt.Sprintf("Expected number, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDEmailObfuscation):
			if v, ok := action.Value.(string); ok {
				m.EmailObfuscation = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for email_obfuscation", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDExplicitCacheControl):
			if v, ok := action.Value.(string); ok {
				m.ExplicitCacheControl = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for explicit_cache_control", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDForwardingURL):
			if valMap, ok := action.Value.(map[string]interface{}); ok {
				var fwData PageRuleActionsForwardingURLModel
				if urlVal, ok := valMap["url"].(string); ok {
					fwData.URL = types.StringValue(urlVal)
				} else {
					diags.AddWarning("Invalid type for forwarding_url.url", fmt.Sprintf("Expected string, got %T", valMap["url"]))
				}
				if scVal, ok := valMap["status_code"].(float64); ok { // JSON number
					fwData.StatusCode = types.Int64Value(int64(scVal))
				} else {
					diags.AddWarning("Invalid type for forwarding_url.status_code", fmt.Sprintf("Expected number, got %T", valMap["status_code"]))
				}
				// Create the NestedObject
				obj, d := customfield.NewObject(ctx, &fwData)
				diags.Append(d...)
				m.ForwardingURL = obj
			} else {
				diags.AddWarning("Invalid type for forwarding_url value", fmt.Sprintf("Expected map[string]interface{}, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDHostHeaderOverride):
			if v, ok := action.Value.(string); ok {
				m.HostHeaderOverride = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for host_header_override", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDIPGeolocation):
			if v, ok := action.Value.(string); ok {
				m.IPGeolocation = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for ip_geolocation", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDMirage):
			if v, ok := action.Value.(string); ok {
				m.Mirage = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for mirage", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDOpportunisticEncryption):
			if v, ok := action.Value.(string); ok {
				m.OpportunisticEncryption = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for opportunistic_encryption", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDOriginErrorPagePassThru):
			if v, ok := action.Value.(string); ok {
				m.OriginErrorPagePassThru = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for origin_error_page_pass_thru", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDPolish):
			if v, ok := action.Value.(string); ok {
				m.Polish = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for polish", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDResolveOverride):
			if v, ok := action.Value.(string); ok {
				m.ResolveOverride = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for resolve_override", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDRespectStrongEtag):
			if v, ok := action.Value.(string); ok {
				m.RespectStrongEtag = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for respect_strong_etag", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDResponseBuffering):
			if v, ok := action.Value.(string); ok {
				m.ResponseBuffering = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for response_buffering", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDRocketLoader):
			if v, ok := action.Value.(string); ok {
				m.RocketLoader = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for rocket_loader", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDSecurityLevel):
			if v, ok := action.Value.(string); ok {
				m.SecurityLevel = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for security_level", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDSortQueryStringForCache):
			if v, ok := action.Value.(string); ok {
				m.SortQueryStringForCache = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for sort_query_string_for_cache", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDSSL):
			if v, ok := action.Value.(string); ok {
				m.SSL = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for ssl", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDTrueClientIPHeader):
			if v, ok := action.Value.(string); ok {
				m.TrueClientIPHeader = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for true_client_ip_header", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		case string(page_rules.PageRuleActionsIDWAF):
			if v, ok := action.Value.(string); ok {
				m.WAF = types.StringValue(v)
			} else {
				diags.AddWarning("Invalid type for waf", fmt.Sprintf("Expected string, got %T", action.Value))
			}
		// TODO: Add cases for cache_key_fields and cache_ttl_by_status (more complex decoding)
		default:
			tflog.Warn(ctx, "Unknown Page Rule action ID received from API", map[string]interface{}{"id": action.ID})
		}
	}

	return diags
}

func convertToStringSlice(b []basetypes.StringValue) []string {
	ss := []string{}
	for _, v := range b {
		ss = append(ss, v.ValueString())
	}
	return ss
}
