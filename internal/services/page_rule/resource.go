// File generated from our OpenAPI spec by Stainless. See CONTRIBUTING.md for details.

package page_rule

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/cloudflare/cloudflare-go/v4"
	"github.com/cloudflare/cloudflare-go/v4/option"
	"github.com/cloudflare/cloudflare-go/v4/page_rules"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/apijson"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/importpath"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/logging"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.ResourceWithConfigure = (*PageRuleResource)(nil)
var _ resource.ResourceWithModifyPlan = (*PageRuleResource)(nil)
var _ resource.ResourceWithImportState = (*PageRuleResource)(nil)

func NewResource() resource.Resource {
	return &PageRuleResource{}
}

// PageRuleResource defines the resource implementation.
type PageRuleResource struct {
	client *cloudflare.Client
}

func (r *PageRuleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_page_rule"
}

func (r *PageRuleResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*cloudflare.Client)

	if !ok {
		resp.Diagnostics.AddError(
			"unexpected resource configure type",
			fmt.Sprintf("Expected *cloudflare.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.client = client
}

func (r *PageRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data *PageRuleModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	dataBytes, err := data.MarshalJSON()
	if err != nil {
		resp.Diagnostics.AddError("failed to serialize http request", err.Error())
		return
	}
	res := new(http.Response)
	env := PageRuleResultEnvelope{*data}
	_, err = r.client.PageRules.New(
		ctx,
		page_rules.PageRuleNewParams{
			ZoneID: cloudflare.F(data.ZoneID.ValueString()),
		},
		option.WithRequestBody("application/json", dataBytes),
		option.WithResponseBodyInto(&res),
		option.WithMiddleware(logging.Middleware(ctx)),
	)
	if err != nil {
		resp.Diagnostics.AddError("failed to make http request", err.Error())
		return
	}
	bytes, _ := io.ReadAll(res.Body)
	err = apijson.UnmarshalComputed(bytes, &env)
	if err != nil {
		resp.Diagnostics.AddError("failed to deserialize http request", err.Error())
		return
	}
	data = &env.Result

	diags := r.readAndSetState(ctx, data.ZoneID.ValueString(), data.ID.ValueString(), data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PageRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data *PageRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state *PageRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	dataBytes, err := data.MarshalJSONForUpdate(*state)
	if err != nil {
		resp.Diagnostics.AddError("failed to serialize http request", err.Error())
		return
	}
	tflog.Debug(ctx, "PageRule Update Request Payload", map[string]interface{}{"payload": string(dataBytes)})

	res := new(http.Response)
	env := PageRuleResultEnvelope{*data}
	_, err = r.client.PageRules.Update(
		ctx,
		data.ID.ValueString(),
		page_rules.PageRuleUpdateParams{
			ZoneID: cloudflare.F(data.ZoneID.ValueString()),
		},
		option.WithRequestBody("application/json", dataBytes),
		option.WithResponseBodyInto(&res),
		option.WithMiddleware(logging.Middleware(ctx)),
	)
	if err != nil {
		resp.Diagnostics.AddError("failed to make http request", err.Error())
		return
	}
	bytes, _ := io.ReadAll(res.Body)
	tflog.Debug(ctx, "PageRule Update Response Body", map[string]interface{}{"status_code": res.StatusCode, "body": string(bytes)})

	err = apijson.UnmarshalComputed(bytes, &env)
	if err != nil {
		resp.Diagnostics.AddError("failed to deserialize http response", err.Error())
		return
	}
	updatedData := &env.Result

	updatedData.ID = data.ID
	updatedData.ZoneID = data.ZoneID

	diags := r.readAndSetState(ctx, data.ZoneID.ValueString(), data.ID.ValueString(), data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

type apiTargetConstraint struct {
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type apiTarget struct {
	Target     string              `json:"target"`
	Constraint apiTargetConstraint `json:"constraint"`
}

type apiActionValue struct {
	ID    string      `json:"id"`
	Value interface{} `json:"value,omitempty"`
}

// Envelope for reading API response, including the list-based targets/actions
type pageRuleAPIReadEnvelope struct {
	Success bool                   `json:"success"`
	Result  *pageRuleAPIReadResult `json:"result"`
}

type pageRuleAPIReadResult struct {
	ID         types.String      `json:"id"`
	Priority   types.Int64       `json:"priority"`
	Status     types.String      `json:"status"`
	CreatedOn  timetypes.RFC3339 `json:"created_on" format:"date-time"`
	ModifiedOn timetypes.RFC3339 `json:"modified_on" format:"date-time"`
	Targets    []apiTarget       `json:"targets"`
	Actions    []apiActionValue  `json:"actions"`
}

func (r *PageRuleResource) readAndSetState(ctx context.Context, zoneID, pageRuleID string, state *PageRuleModel) diag.Diagnostics {
	var diags diag.Diagnostics
	tflog.Debug(ctx, "Reading Page Rule from API", map[string]interface{}{"zone_id": zoneID, "pagerule_id": pageRuleID})

	res := new(http.Response)
	env := pageRuleAPIReadEnvelope{}
	_, err := r.client.PageRules.Get(
		ctx,
		pageRuleID,
		page_rules.PageRuleGetParams{
			ZoneID: cloudflare.F(zoneID),
		},
		option.WithResponseBodyInto(&res),
		option.WithMiddleware(logging.Middleware(ctx)),
	)
	if res != nil && res.StatusCode == 404 {
		diags.AddWarning("Resource not found during read", "The resource was not found on the server and will be removed from state.")
		state = nil
		return diags
	}
	if err != nil {
		diags.AddError("failed to make http request during read", err.Error())
		return diags
	}
	bytes, _ := io.ReadAll(res.Body)
	err = apijson.Unmarshal(bytes, &env)
	if err != nil {
		diags.AddError("failed to deserialize http response during read", err.Error())
		return diags
	}

	if !env.Success || env.Result == nil {
		diags.AddError("API returned unsuccessful or nil result during read", fmt.Sprintf("%+v", env))
		return diags
	}

	apiResult := env.Result

	state.ID = apiResult.ID
	state.ZoneID = types.StringValue(zoneID)
	state.Priority = apiResult.Priority
	state.Status = apiResult.Status
	state.CreatedOn = apiResult.CreatedOn
	state.ModifiedOn = apiResult.ModifiedOn

	if len(apiResult.Targets) > 0 && apiResult.Targets[0].Target == "url" && apiResult.Targets[0].Constraint.Operator == "matches" {
		state.Target = types.StringValue(apiResult.Targets[0].Constraint.Value)
	} else {
		tflog.Warn(ctx, "Unexpected Page Rule target format received from API", map[string]interface{}{"targets": apiResult.Targets})
		state.Target = types.StringNull()
	}

	state.Actions = &PageRuleActionsModel{}
	decodeDiags := state.Actions.Decode(ctx, apiResult.Actions)
	diags.Append(decodeDiags...)

	tflog.Debug(ctx, "Successfully read and processed Page Rule state from API")
	return diags
}

func (r *PageRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data *PageRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags := r.readAndSetState(ctx, data.ZoneID.ValueString(), data.ID.ValueString(), data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PageRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data *PageRuleModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.PageRules.Delete(
		ctx,
		data.ID.ValueString(),
		page_rules.PageRuleDeleteParams{
			ZoneID: cloudflare.F(data.ZoneID.ValueString()),
		},
		option.WithMiddleware(logging.Middleware(ctx)),
	)
	if err != nil {
		resp.Diagnostics.AddError("failed to make http request", err.Error())
		return
	}
}

func (r *PageRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	var data *PageRuleModel = new(PageRuleModel)

	path_zone_id := ""
	path_pagerule_id := ""
	diags := importpath.ParseImportID(
		req.ID,
		"<zone_id>/<pagerule_id>",
		&path_zone_id,
		&path_pagerule_id,
	)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = r.readAndSetState(ctx, path_zone_id, path_pagerule_id, data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data == nil {
		resp.Diagnostics.AddError("Import failed", fmt.Sprintf("Could not find Page Rule with ID %s in zone %s", path_pagerule_id, path_zone_id))
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PageRuleResource) ModifyPlan(_ context.Context, _ resource.ModifyPlanRequest, _ *resource.ModifyPlanResponse) {
}
