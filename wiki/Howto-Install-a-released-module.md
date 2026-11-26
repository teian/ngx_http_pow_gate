# How to install a released module

Goal: load the prebuilt, signed module into an nginx you already run, without a
Rust toolchain.

## 1. Find the three facts that must match

A dynamic module loads **only** into the exact nginx version it was built for,
with the same libc and CPU architecture.

```bash
nginx -v        # e.g. nginx/1.31.10  → the nginx version
uname -m        # x86_64 → amd64, aarch64 → arm64
ldd --version 2>&1 | head -1   # mentions "musl" on Alpine, otherwise glibc
```

Releases cover the current nginx **mainline** and **stable** versions. If your
nginx is older, either upgrade nginx or take the older
[release](https://github.com/teian/ngx_http_pow_gate/releases) that was built for it — or
[build from source](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/build.md).

## 2. Download the matching file

File names carry all three facts:

```text
ngx_http_pow_gate_module-<module-version>-nginx<nginx-version>-<libc>-<arch>.so
```

From the [release page](https://github.com/teian/ngx_http_pow_gate/releases) download that `.so`, its `.sig` and `.pem`,
and `SHA256SUMS`. With the GitHub CLI:

```bash
module=ngx_http_pow_gate_module-<module-version>-nginx<nginx-version>-glibc-amd64.so
gh release download v<module-version> --repo teian/ngx_http_pow_gate \
  --pattern "$module*" --pattern SHA256SUMS
```

## 3. Verify it

```bash
sha256sum -c --ignore-missing SHA256SUMS
gh attestation verify "$module" --repo teian/ngx_http_pow_gate
```

The first command checks integrity, the second that the file was built by this
repository's release workflow. The cosign command for the keyless signature is
in each release's notes.

## 4. Install and load

```bash
sudo cp "$module" /etc/nginx/modules/ngx_http_pow_gate_module.so
```

At the very top of `nginx.conf`, before `http {`:

```nginx
load_module modules/ngx_http_pow_gate_module.so;
```

```bash
sudo nginx -t
```

`nginx -t` passing means the module loaded. The gate is still off everywhere —
continue with [Set up your first gate](Howto-Set-up-your-first-gate).

## If it does not load

| Message | Cause |
| --- | --- |
| `module ... is not binary compatible` | nginx version or build options differ from the module's. Re-check `nginx -v` and pick the exact match. |
| `cannot open shared object file` | Wrong path in `load_module`, or wrong libc (a glibc module on Alpine, or the reverse). |
| `wrong ELF class` / `Exec format error` | Wrong architecture. |

More in [build.md › Troubleshooting](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/build.md#troubleshooting).
