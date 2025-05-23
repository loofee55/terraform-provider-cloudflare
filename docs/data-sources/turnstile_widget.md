---
page_title: "cloudflare_turnstile_widget Data Source - Cloudflare"
subcategory: ""
description: |-
  
---

# cloudflare_turnstile_widget (Data Source)



## Example Usage

```terraform
data "cloudflare_turnstile_widget" "example_turnstile_widget" {
  account_id = "023e105f4ecef8ad9ca31a8372d0c353"
  sitekey = "0x4AAF00AAAABn0R22HWm-YUc"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `account_id` (String) Identifier

### Optional

- `filter` (Attributes) (see [below for nested schema](#nestedatt--filter))
- `sitekey` (String) Widget item identifier tag.

### Read-Only

- `bot_fight_mode` (Boolean) If bot_fight_mode is set to `true`, Cloudflare issues computationally
expensive challenges in response to malicious bots (ENT only).
- `clearance_level` (String) If Turnstile is embedded on a Cloudflare site and the widget should grant challenge clearance,
this setting can determine the clearance level to be set
Available values: "no_clearance", "jschallenge", "managed", "interactive".
- `created_on` (String) When the widget was created.
- `domains` (List of String)
- `ephemeral_id` (Boolean) Return the Ephemeral ID in /siteverify (ENT only).
- `id` (String) Widget item identifier tag.
- `mode` (String) Widget Mode
Available values: "non-interactive", "invisible", "managed".
- `modified_on` (String) When the widget was modified.
- `name` (String) Human readable widget name. Not unique. Cloudflare suggests that you
set this to a meaningful string to make it easier to identify your
widget, and where it is used.
- `offlabel` (Boolean) Do not show any Cloudflare branding on the widget (ENT only).
- `region` (String) Region where this widget can be used. This cannot be changed after creation.
Available values: "world", "china".
- `secret` (String, Sensitive) Secret key for this widget.

<a id="nestedatt--filter"></a>
### Nested Schema for `filter`

Optional:

- `direction` (String) Direction to order widgets.
Available values: "asc", "desc".
- `order` (String) Field to order widgets by.
Available values: "id", "sitekey", "name", "created_on", "modified_on".


