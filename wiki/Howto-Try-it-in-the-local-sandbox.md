# How to try it in the local sandbox

Goal: a running nginx with the gate on your own machine, to click through the
challenge and experiment with configuration. Needs Docker with `docker compose`
and a checkout of the repository.

```bash
git clone https://github.com/teian/ngx_http_pow_gate.git
cd ngx_http_pow_gate
./scripts/dev.sh up
```

This builds the module, starts nginx on <http://localhost:12222> and prints what
to try.

| Request | Expected |
| --- | --- |
| open `http://localhost:12222/` in a browser | challenge page, then the result page |
| `curl -i localhost:12222/` | challenge HTML — no clearance |
| `curl localhost:12222/healthz` | `ok` — excluded path, never gated |
| `curl -A verifierbot localhost:12222/` | upstream content — verified good bot |

## Commands

```bash
./scripts/dev.sh check    # smoke checks + a full scripted handshake; exits 1 on failure
./scripts/dev.sh reload   # nginx -t, then apply an edited docker/nginx.dev.conf
./scripts/dev.sh logs     # follow the nginx logs
./scripts/dev.sh down     # stop and remove, including volumes
```

`check` needs Node.js 20 or newer for the handshake; without it the curl checks
still run.

## Experiment

Edit [`docker/nginx.dev.conf`](https://github.com/teian/ngx_http_pow_gate/blob/main/docker/nginx.dev.conf) — difficulty, decision
map, exclusions — then `./scripts/dev.sh reload`. Only changes to the module's
own code need `./scripts/dev.sh up` again.

```bash
DEV_PORT=9090 ./scripts/dev.sh up                  # another host port
DEV_TARGET=nginx-smoke-alpine ./scripts/dev.sh up  # the musl build
```

The sandbox page also has a *"Drop clearance, then POST"* button: it expires the
clearance, submits a form, and shows the submission arriving intact after the
solve.

Reference: [testing.md](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/testing.md).
