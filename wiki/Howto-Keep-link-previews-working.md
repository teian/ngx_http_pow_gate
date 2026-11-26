# How to keep link previews working

Goal: a link to your gated site still shows a title and image when someone
posts it in a chat or on a social network.

Preview fetchers request the page once and read its `<title>` and Open Graph
tags. They run no JavaScript, so they get the challenge page and the preview
stays empty. The fix is to let them through, as narrowly as possible.

## 1. Decide how much to trust a User-Agent

| Fetcher | Can be checked? |
| --- | --- |
| Meta (`facebookexternalhit`), X (`Twitterbot`), LinkedIn (`LinkedInBot`), Telegram (`TelegramBot`) | yes, each operator owns the network it fetches from, so the client's ASN confirms it |
| Slack, Discord, Mastodon, Iframely, Embedly | no, they fetch from shared cloud addresses |
| WhatsApp, Signal, iMessage | no, the sender's own phone fetches the page |

For the second and third group the User-Agent is all there is, and anyone can
send it. Letting them in is a bounded leak, not a verified exception.

## 2. Include the example

[`examples/link-previews.conf`](https://github.com/teian/ngx_http_pow_gate/blob/main/examples/link-previews.conf)
implements both tiers. It needs `$pow_client_asn` from
[`examples/asn-policy.conf`](https://github.com/teian/ngx_http_pow_gate/blob/main/examples/asn-policy.conf)
(the optional GeoIP2 module with an ASN database).

```nginx
http {
    include /etc/nginx/pow/asn-policy.conf;      # defines $pow_client_asn
    map $http_user_agent $pow_decision { … }     # your existing policy
    include /etc/nginx/pow/link-previews.conf;

    server {
        location / {
            pow_gate          on;
            pow_gate_decision $pow_decision_with_previews;
            limit_req         zone=pow_previews burst=6 nodelay;
            proxy_pass http://backend;
        }
    }
}
```

A recognised preview fetcher is allowed; every other request keeps the
decision your own map gave it. A client that claims to be Meta's fetcher from
another network is not recognised and is challenged.

## 3. Understand the limit

Admitted previews are limited to 12 requests per minute per address. Regular
visitors are not counted. A real fetcher asks for a URL once; a scraper that
borrows the User-Agent is cut off quickly unless it also rotates addresses.

If that leak is not acceptable, delete the `unverified` line from the first map
in the include. Slack, Discord and the phone-based apps then show no preview.

## 4. Check it

```bash
curl -sA 'facebookexternalhit/1.1' https://example.com/ | grep -c 'og:title'
```

From an address outside Meta's network this must print `0` (you got the
challenge page). Post a link in the real apps to see the previews.
