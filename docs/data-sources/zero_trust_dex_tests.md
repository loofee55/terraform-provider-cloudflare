---
page_title: "cloudflare_zero_trust_dex_tests Data Source - Cloudflare"
subcategory: ""
description: |-
  
---

# cloudflare_zero_trust_dex_tests (Data Source)



## Example Usage

```terraform
data "cloudflare_zero_trust_dex_tests" "example_zero_trust_dex_tests" {
  account_id = "01a7362d577a6c3019a474fd6f485823"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `account_id` (String)

### Optional

- `max_items` (Number) Max items to fetch, default: 1000

### Read-Only

- `result` (Attributes List) The items returned by the data source (see [below for nested schema](#nestedatt--result))

<a id="nestedatt--result"></a>
### Nested Schema for `result`

Read-Only:

- `data` (Attributes) The configuration object which contains the details for the WARP client to conduct the test. (see [below for nested schema](#nestedatt--result--data))
- `description` (String) Additional details about the test.
- `enabled` (Boolean) Determines whether or not the test is active.
- `interval` (String) How often the test will run.
- `name` (String) The name of the DEX test. Must be unique.
- `target_policies` (Attributes List) DEX rules targeted by this test (see [below for nested schema](#nestedatt--result--target_policies))
- `targeted` (Boolean)
- `test_id` (String) The unique identifier for the test.

<a id="nestedatt--result--data"></a>
### Nested Schema for `result.data`

Read-Only:

- `host` (String) The desired endpoint to test.
- `kind` (String) The type of test.
- `method` (String) The HTTP request method type.


<a id="nestedatt--result--target_policies"></a>
### Nested Schema for `result.target_policies`

Read-Only:

- `default` (Boolean) Whether the DEX rule is the account default
- `id` (String) The id of the DEX rule
- `name` (String) The name of the DEX rule


