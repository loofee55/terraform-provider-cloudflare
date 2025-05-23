---
page_title: "cloudflare_cloudforce_one_request Resource - Cloudflare"
subcategory: ""
description: |-
  
---

# cloudflare_cloudforce_one_request (Resource)



## Example Usage

```terraform
resource "cloudflare_cloudforce_one_request" "example_cloudforce_one_request" {
  account_id = "023e105f4ecef8ad9ca31a8372d0c353"
  content = "What regions were most effected by the recent DoS?"
  priority = "routine"
  request_type = "Victomology"
  summary = "DoS attack"
  tlp = "clear"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `account_id` (String) Identifier.

### Optional

- `content` (String) Request content.
- `priority` (String) Priority for analyzing the request.
- `request_type` (String) Requested information from request.
- `summary` (String) Brief description of the request.
- `tlp` (String) The CISA defined Traffic Light Protocol (TLP).
Available values: "clear", "amber", "amber-strict", "green", "red".

### Read-Only

- `completed` (String)
- `created` (String)
- `id` (String) UUID.
- `message_tokens` (Number) Tokens for the request messages.
- `readable_id` (String) Readable Request ID.
- `request` (String) Requested information from request.
- `status` (String) Request Status.
Available values: "open", "accepted", "reported", "approved", "completed", "declined".
- `tokens` (Number) Tokens for the request.
- `updated` (String)

## Import

Import is supported using the following syntax:

```shell
$ terraform import cloudflare_cloudforce_one_request.example '<account_id>/<request_id>'
```
