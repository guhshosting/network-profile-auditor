# JSON schema 1.0

> Release context: see [qualified platforms, runtime requirements and package scope](RELEASE-QUALIFICATION.md).


`--json` emits one UTF-8 JSON object followed by a newline. No BOM or progress text is written to stdout. Usage/unexpected errors go to stderr. NLM unavailability still emits an audit object with warnings and exits 3. `--all --json` includes disconnected/remembered NLM networks.

Required top-level fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | String `1.0`; breaking changes require a new major schema version |
| `application_version` | String `1.0.0` |
| `selection` | `current` or `all` |
| `profile_api_available` | NLM network enumeration started successfully |
| `profile_enumeration_complete` | NLM network enumeration reached its end |
| `interface_api_available` | Local interface table obtained successfully |
| `networks` | NLM networks: `id`, `name`, `connected`, connectivity and domain state |
| `profiles` | Profile projection of the same networks: `id`, `network_id`, `name`, `category_raw`, `category` |
| `interfaces` | All IP Helper interfaces, irrespective of selection |
| `correlations` | One record per NLM network connection; many-to-many references allowed |
| `findings` | Factual records with `code`, `subject`, `message` |
| `warnings` | Array of strings describing unavailable/partial metadata |
| `limitations` | Array of strings describing interpretation limits |

The profile ID equals the NLM network ID: this is a category-bearing projection, not a second independent Windows profile inventory. GUID strings use canonical `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` spelling. Missing identity/name is `null`, not an invented value. Correlations with unavailable network IDs cannot be joined by identity. Windows BSTR embedded NULs are preserved and escaped.

Networks and correlations include `windows_connectivity_raw` (number or null), `windows_connectivity_flags` (array), `domain_type_raw` (number or null), `domain_type` (label), and `connected` (boolean or null). Flags: `disconnected`, `ipv4_no_traffic`, `ipv6_no_traffic`, `ipv4_subnet`, `ipv4_local_network`, `ipv4_internet`, and corresponding IPv6 labels. Unknown bits become `unknown_bits(0x...)`. A null raw connectivity has an empty flag array; it must not be interpreted as disconnected. `connected` is the Windows `IsConnected` property, not a connectivity test.

Category labels are `public`, `private`, `domain_authenticated`, `unknown(0x...)`, or `unavailable`. Domain labels are `non_domain_network`, `domain_network_not_authenticated`, `domain_authenticated`, `unknown(0x...)`, or `unavailable`. Raw values allow future enums to remain representable.

Interfaces include `id`, `friendly_name`, `description`, numeric `index`, **decimal string** `luid` (avoids JavaScript 64-bit precision loss), `type_raw`, `oper_status_raw`, `oper_status`, `tunnel_type_raw`, `hardware_interface`, `filter_interface`, and `virtual_vpn_candidate`. Operational labels: `up`, `down`, `testing`, `unknown`, `dormant`, `not_present`, `lower_layer_down`, or future `unknown(0x...)`.

Correlations include `network_id`, `connection_id`, `adapter_id`, and `interface_id`. `interface_id` is null if GUID correlation failed, while `adapter_id` preserves the NLM reference. Missing correlation may reflect incomplete APIs, compartments, logical interfaces, or changing state. A complete network enumeration does not imply every per-network property/connection enumeration succeeded; inspect warnings.

Consumers should accept added fields and unknown labels. Finding codes in 1.0: `multiple_active_profiles`, `public_profile`, `private_profile`, `domain_authenticated_profile`, `no_connectivity`, `active_interface_without_profile`, `profile_interface_unavailable`, `virtual_vpn_candidate`. Findings never cause nonzero exit status. Messages are explanatory text, not stable identifiers.
