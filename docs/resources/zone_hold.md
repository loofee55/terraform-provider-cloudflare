---
page_title: "cloudflare_zone_hold Resource - Cloudflare"
subcategory: ""
description: |-
  
---

# cloudflare_zone_hold (Resource)



## Example Usage

```terraform
resource "cloudflare_zone_hold" "example_zone_hold" {
  zone_id = "023e105f4ecef8ad9ca31a8372d0c353"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `zone_id` (String) Identifier.

### Optional

- `hold_after` (String) If `hold_after` is provided and future-dated, the hold will be temporarily disabled,
then automatically re-enabled by the system at the time specified
in this RFC3339-formatted timestamp. A past-dated `hold_after` value will have
no effect on an existing, enabled hold. Providing an empty string will set its value
to the current time.
- `include_subdomains` (Boolean) If `true`, the zone hold will extend to block any subdomain of the given zone, as well
as SSL4SaaS Custom Hostnames. For example, a zone hold on a zone with the hostname
'example.com' and include_subdomains=true will block 'example.com',
'staging.example.com', 'api.staging.example.com', etc.

### Read-Only

- `hold` (Boolean)
- `id` (String) Identifier.

## Import

Import is supported using the following syntax:

```shell
$ terraform import cloudflare_zone_hold.example '<zone_id>'
```
