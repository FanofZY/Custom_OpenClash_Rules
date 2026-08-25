# Personal rules

This directory is the only place intended for manually maintained personal
rules. Upstream synchronization never writes these files.

For ordered rules that already include a target policy, put them in
`Custom_Prepend.list` using `KIND,VALUE,POLICY`. These rules are inserted before
all upstream rules, so the first matching rule wins. Exact duplicate lines are
removed automatically; assigning the same match key to different policies is
treated as an error.

The policy names `DIRECT`, `PROXY`, and `REJECT` are portable aliases. `DIRECT`
maps to `🎯 全球直连`; `PROXY` maps to the template's main proxy group. Regional
groups such as `🇯🇵 日本节点` and `🇺🇸 美国节点` are preserved when the template
defines them. Minimal GFW templates do not define regional groups, so those
rules fall back to `🚀 手动选择` or `🚀 故障转移` in those two templates.

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
- Put ordered, policy-bearing rules in `Custom_Prepend.list`.
- Blank lines and lines beginning with `#` or `;` are ignored.
- In the Direct/Proxy/Reject files, do not append a policy name; the filename
  determines the policy. `Custom_Prepend.list` is the exception and requires
  the policy as its third column.

During each build, personal rules take precedence over upstream direct and
proxy rules. If the same match key appears in more than one personal policy,
the build fails instead of choosing silently.

Generated files are written to `dist/` and must not be edited manually.
