---
page_title: "cloudflare_pages_domains Data Source - Cloudflare"
subcategory: ""
description: |-
  
---

# cloudflare_pages_domains (Data Source)



## Example Usage

```terraform
data "cloudflare_pages_domains" "example_pages_domains" {
  account_id = "023e105f4ecef8ad9ca31a8372d0c353"
  project_name = "this-is-my-project-01"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `account_id` (String) Identifier
- `project_name` (String) Name of the project.

### Optional

- `max_items` (Number) Max items to fetch, default: 1000

### Read-Only

- `result` (Attributes List) The items returned by the data source (see [below for nested schema](#nestedatt--result))

<a id="nestedatt--result"></a>
### Nested Schema for `result`

Read-Only:

- `certificate_authority` (String) Available values: "google", "lets_encrypt".
- `created_on` (String)
- `domain_id` (String)
- `id` (String)
- `name` (String)
- `status` (String) Available values: "initializing", "pending", "active", "deactivated", "blocked", "error".
- `validation_data` (Attributes) (see [below for nested schema](#nestedatt--result--validation_data))
- `verification_data` (Attributes) (see [below for nested schema](#nestedatt--result--verification_data))
- `zone_tag` (String)

<a id="nestedatt--result--validation_data"></a>
### Nested Schema for `result.validation_data`

Read-Only:

- `error_message` (String)
- `method` (String) Available values: "http", "txt".
- `status` (String) Available values: "initializing", "pending", "active", "deactivated", "error".
- `txt_name` (String)
- `txt_value` (String)


<a id="nestedatt--result--verification_data"></a>
### Nested Schema for `result.verification_data`

Read-Only:

- `error_message` (String)
- `status` (String) Available values: "pending", "active", "deactivated", "blocked", "error".


