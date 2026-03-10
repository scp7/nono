# Network Filtering with nono

## Policy Format
```json
{
  "allow_domains": ["*.example.com", "safe-site.org"],
  "block_content_types": ["image/*", "application/javascript"]
}
```

## Example: Block JavaScript and Images
1. Create a policy file:
```json
{
  "allow_domains": ["*.example.com"],
  "block_content_types": ["image/*", "application/javascript"]
}
```
2. Run with nono:
```bash
nono run --network-policy policy.json curl https://example.com
```

## Limitations
- HTTPS content-type filtering requires MITM (not implemented in this version)
- Works best with HTTP traffic for demonstration purposes