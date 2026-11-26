# How to set up your first gate

Goal: one site behind the gate, with your own network exempt and the paths that
must stay open excluded. Assumes the module is
[installed](Howto-Install-a-released-module).

## 1. Create the server secret

The gate signs challenges and clearance cookies with one HMAC key. nginx refuses
to start with the gate on and no readable key of at least 16 bytes.

```bash
sudo install -d -m 750 -o root -g nginx /etc/pow
sudo sh -c 'head -c 32 /dev/urandom > /etc/pow/hmac.key'
sudo chown nginx:nginx /etc/pow/hmac.key
sudo chmod 600 /etc/pow/hmac.key
```

Use the user your nginx **workers** run as (`nginx`, `www-data`, …). A key the
worker cannot read makes the gate fail closed: clients stay on the challenge
page and `/.pow/` answers `503`.

## 2. Add the configuration

```nginx
load_module modules/ngx_http_pow_gate_module.so;

http {
    pow_gate_hmac_key_file /etc/pow/hmac.key;
    pow_gate_difficulty    500000;

    # Who skips the gate entirely
    geo $pow_trusted {
        default      0;
        10.0.0.0/8   1;
    }

    # What happens to everyone else
    map $http_user_agent $pow_decision {
        default   challenge;
    }

    server {
        listen 443 ssl;
        server_name example.com;

        # set once — every location inherits
        pow_gate          on;
        pow_gate_trusted  $pow_trusted;
        pow_gate_decision $pow_decision;

        location / { proxy_pass http://backend; }

        # must stay reachable without JavaScript
        location = /robots.txt    { pow_gate off; proxy_pass http://backend; }
        location ^~ /.well-known/ { pow_gate off; proxy_pass http://backend; }
    }
}
```

Set the key, endpoint and policy at `http` and let them inherit. The location
that issues a clearance (`/.pow/`) and the location that checks it must resolve
to the same values, or clearances will not validate.

The clearance cookie is `Secure` by default, so serve the site over HTTPS. For
a plain-HTTP test host set `pow_gate_cookie_secure off;`.

## 3. Reload and check

```bash
sudo nginx -t && sudo nginx -s reload

# no clearance → the challenge page
curl -s -o /dev/null -w '%{http_code} %{content_type}\n' https://example.com/
# 200 text/html; charset=utf-8

# excluded path → your upstream's answer
curl -s -o /dev/null -w '%{http_code} %{content_type}\n' https://example.com/robots.txt
```

Then open the site in a browser: a short "Just a moment…" page, then your site.
The challenge answers with status `200`, not a redirect or `403` — monitoring
that only checks the status code will not notice the difference, so check the
body or exclude the monitored path.

## 4. Turn on logging

Do this before you tune anything — see [Read the gate logs](Howto-Read-the-gate-logs).

## Next

- [Let verified search engines through](Howto-Let-verified-search-engines-through)
  before the gate meets your SEO.
- [Exclude paths and APIs](Howto-Exclude-paths-and-APIs) for everything that
  cannot run JavaScript.
- Behind a proxy? [Run behind a load balancer](Howto-Run-behind-a-load-balancer)
  first, or every decision is made on the proxy's address.

Full annotated example: [examples/nginx.conf](https://github.com/teian/ngx_http_pow_gate/blob/main/examples/nginx.conf).
