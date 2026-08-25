# Personal rules

This directory is the only place intended for manually maintained personal
rules. Upstream synchronization never writes these files.

Use one rule per line in the same source format as the upstream `.list` files:

```text
DOMAIN,api.example.com
DOMAIN-SUFFIX,example.com
DOMAIN-KEYWORD,example
DOMAIN-REGEX,^example[0-9]+\.com$
IP-CIDR,192.0.2.0/24
IP-CIDR6,2001:db8::/32
DST-PORT,12345
SRC-PORT,12345
```

- Put direct rules in `Custom_Direct.list`.
- Put proxy rules in `Custom_Proxy.list`.
- Put rejected rules in `Custom_Reject.list`.
- Blank lines and lines beginning with `#` or `;` are ignored.
- Do not append a policy name. The file containing the rule determines its
  policy.

During each build, personal rules take precedence over upstream direct and
proxy rules. If the same match key appears in more than one personal policy,
the build fails instead of choosing silently.

Generated files are written to `dist/` and must not be edited manually.
