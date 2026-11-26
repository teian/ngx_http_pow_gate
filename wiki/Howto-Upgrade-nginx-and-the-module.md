# How to upgrade nginx and the module

A module is tied to one exact nginx version. Upgrading nginx without replacing
the module leaves nginx unable to start; nginx refuses the old module as
`not binary compatible`.

## When a new nginx is released

The repository picks up new nginx mainline and stable releases daily. A rebuild
is published as a new module **patch version** with unchanged code — for
example `v0.6.2` is `v0.6.1` rebuilt for nginx 1.31.10. Watch the
[releases](https://github.com/teian/ngx_http_pow_gate/releases) (GitHub: *Watch → Custom → Releases*).

## Upgrade steps

1. Download and verify the module for the **new** nginx version — see
   [Install a released module](Howto-Install-a-released-module).
2. Stage it next to the current one:

   ```bash
   sudo cp "$module" /etc/nginx/modules/ngx_http_pow_gate_module.so.new
   ```

3. Upgrade the nginx package, then swap the module in before nginx starts with
   the new binary:

   ```bash
   sudo mv /etc/nginx/modules/ngx_http_pow_gate_module.so.new \
           /etc/nginx/modules/ngx_http_pow_gate_module.so
   sudo nginx -t
   ```

4. Restart nginx. A module replacement needs a new master process: use your
   service manager's restart (or nginx's binary-upgrade procedure), not
   `nginx -s reload`.

With container images, build both into one image so they can never drift:

```dockerfile
FROM nginx:1.31.10
COPY ngx_http_pow_gate_module-<module-version>-nginx1.31.10-glibc-amd64.so \
     /etc/nginx/modules/ngx_http_pow_gate_module.so
```

Package managers upgrade nginx on their own schedule. Pin or hold the nginx
package so an unattended upgrade cannot replace nginx underneath the module.

## What visitors notice

- **Restart with the default in-memory ledger:** outstanding clearances and
  challenges are invalidated; everyone solves once more. A graceful reload does
  not have this effect.
- **With [Redis](Howto-Run-several-gateways-with-Redis):** clearances survive
  the restart, and gateways can be upgraded one at a time.
- **A new solver** is picked up automatically; its URL is content-hashed.

## Module upgrades with code changes

Read the release notes first. Releases that change the protocol or cookie scope
say so and usually cost one fresh solve per client — for example 0.5.0, which
introduced protocol v2 and scoped cookie names.

## Rolling back

Keep the previous nginx package and its matching module together. Roll back
both or neither.

Reference: [releasing.md](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/releasing.md).
