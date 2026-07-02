# Releasing

How versions, tags, release titles, and artifacts fit together, and the steps to
cut a release. Releases are **always manual** — automation stops at the PR
(see [nginx version bumps](#nginx-version-bumps)).

- [The two version axes](#the-two-version-axes)
- [Tags](#tags)
- [Release titles](#release-titles)
- [Artifact naming](#artifact-naming)
- [Cutting a release](#cutting-a-release)
- [nginx version bumps](#nginx-version-bumps)

---

## The two version axes

An nginx dynamic module has two independent version axes, and conflating them
causes wrong downloads:

1. **Module version** — the code in this repo. SemVer, single source of truth is
   `version` in [`src/ngx-http-pow-gate/Cargo.toml`](../src/ngx-http-pow-gate/Cargo.toml)
   (keep `pow-gate-core` in lockstep).
2. **nginx version** — what the `.so` was built against. Single source of truth
   is `ARG NGINX_VERSION` in [`docker/Dockerfile`](../docker/Dockerfile). A
   module `.so` loads **only** into the exact nginx version it was built for.

The module version lives in the tag; the nginx version lives in the artifact
name and the release title. Bumping nginx alone is a new release of the *same*
module version (patch-bump the module only when code changed).

## Tags

- Format: `v<module-version>`, e.g. `v0.2.0` — plain SemVer, nothing else.
- Annotated tags (`git tag -a`), message = one-paragraph summary.
- Pushing a `v*` tag triggers [`release.yml`](../.github/workflows/release.yml):
  reproducibility double-build for every {libc × arch}, SLSA provenance, keyless
  cosign signatures, `SHA256SUMS`, and the GitHub release with all artifacts.

## Release titles

Template:

```
v<module-version> — <short content phrase> (nginx <nginx-version>)
```

| Occasion | Title |
| --- | --- |
| Feature release | `v0.2.0 — per-path difficulty & challenge page theming (nginx 1.31.2)` |
| Bugfix release | `v0.1.1 — fix clearance cookie SameSite handling (nginx 1.31.2)` |
| Pure nginx rebuild | `v0.1.1 — rebuild for nginx 1.31.3` |

Rules:

- **Tag first** — the releases list sorts and scans by version.
- **nginx version always in the title** — it is the single most important
  compatibility fact; readers must see whether the `.so` fits their nginx
  without clicking. For a pure rebuild it *is* the content ("rebuild for
  nginx X"); otherwise it goes in a trailing parenthesis.
- **Content is a phrase, not a sentence** — lowercase like a commit subject, no
  trailing period, ≤ ~70 characters (GitHub truncates long titles in the list).
- No word "release" in the title — redundant.

## Artifact naming

Both axes plus the platform, so a downloaded file is self-describing:

```
ngx_http_pow_gate_module-<module-version>-nginx<nginx-version>-<libc>-<arch>.so
ngx_http_pow_gate_module-0.1.1-nginx1.31.2-glibc-amd64.so
```

`release.yml` derives both versions from their sources of truth at build time —
never hand-edit artifact names. `<libc>` ∈ {`glibc`, `musl`}, `<arch>` ∈
{`amd64`, `arm64`}.

## Cutting a release

1. Ensure `main` is green and the module version in `Cargo.toml` is what you
   want to ship (bump it in a normal PR if not).
2. Tag and push:

   ```console
   git tag -a v0.1.1 -m "…"
   git push origin v0.1.1
   ```

3. `release.yml` runs: if any {libc × arch} build is not byte-identical across
   two independent builds, the release **fails** — nothing is published.
4. When the release appears, edit it: set the title per
   [Release titles](#release-titles) and write the notes (highlights, artifact
   table, verification commands — see the previous release as the pattern).

## nginx version bumps

[`nginx-update.yml`](../.github/workflows/nginx-update.yml) checks daily for a
new nginx release. When one exists, [`scripts/update-nginx.sh`](../scripts/update-nginx.sh)
refreshes every pin (version, tarball SHA256, image digests, docs), the module
is smoke-built against the new nginx on glibc + musl, and a PR is opened.

**Nothing is tagged or published automatically.** Review the PR, merge it, then
cut a release per [Cutting a release](#cutting-a-release) when you want the
rebuilt `.so`s out — usually as a pure rebuild ("`v0.1.1 — rebuild for nginx
1.31.3`") without a module version bump only if the module version at that tag
has not shipped before; if the module version is already released, bump the
patch version first (a tag is immutable once published).

> CI on the auto-PR: PRs created with the default `GITHUB_TOKEN` do not trigger
> other workflows (GitHub's recursion guard). The smoke builds inside
> `nginx-update.yml` are the validation. For full CI on the PR, add a
> fine-grained PAT (contents + pull-requests write) as the `NGINX_UPDATE_TOKEN`
> secret.
