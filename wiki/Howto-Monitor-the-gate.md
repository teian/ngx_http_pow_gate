# How to monitor the gate

Goal: graph what the gate is doing, raise the price when the machine is busy,
and get told about clients that walk into the trap.

## 1. Expose the counters

```nginx
server {
    location = /pow_gate_status {
        pow_gate off;        # a scraper cannot solve a challenge
        allow 127.0.0.1;
        deny  all;
        pow_gate_status;
    }
}
```

```bash
curl -s http://127.0.0.1/pow_gate_status
```

```text
pow_gate_requests_total{result="bypass",reason="clearance"} 48213
pow_gate_requests_total{result="challenge",reason="no_clearance"} 912
pow_gate_requests_total{result="accepted",reason="pow"} 877
pow_gate_requests_total{result="deny",reason="policy"} 15502
pow_gate_load_percent 5
```

The labels are the values of [`$pow_gate_result` and `$pow_gate_reason`](Howto-Read-the-gate-logs).
The numbers cover all workers of this nginx instance and reset on a full
restart. Keep the location private.

Useful ratios:

| Question | Expression |
| --- | --- |
| How many challenged visitors get through? | `accepted` ÷ `challenge` |
| Is someone farming challenges? | `issued` far above `accepted` |
| Are clients' clocks a problem? | `rejected{reason="challenge_expired"}` or `proof_skew` rising |
| Is the replay store full? | any `error{reason="redemption_unavailable"}` |

## 2. Charge more while the machine is busy

```nginx
map $pow_gate_load $pow_load_scale {
    default                  1;
    ~^1\d\d$                 2;   # load at 100–199 % of the CPUs
    ~^[23]\d\d$              4;
    "~^([4-9]\d\d|\d{4,})$"  8;
}
location / {
    pow_gate on;
    pow_gate_difficulty_scale $pow_load_scale;
}
```

Only new challenges get harder. Visitors who already hold a clearance are not
sent back to the challenge page.

## 3. Act on the honeypot

The built-in challenge page has a link no person can see or reach. A client
that requests it is crawling the page source. The gate logs it and answers
`404`:

```text
2026/11/26 10:12:01 [warn] 71#71: *9 pow_gate honeypot hit, client: 203.0.113.9, server: example.com, request: "GET /.pow/trap HTTP/1.1"
```

A fail2ban filter (`/etc/fail2ban/filter.d/pow-gate-honeypot.conf`):

```ini
[Definition]
failregex = pow_gate honeypot hit, client: <HOST>,
```

and a jail:

```ini
[pow-gate-honeypot]
enabled  = true
filter   = pow-gate-honeypot
logpath  = /var/log/nginx/error.log
maxretry = 1
bantime  = 1d
```

Add `Disallow: /.pow/` to `robots.txt` first, so that crawlers which respect it
never see the trap.

## 4. Keep clearances across a restart

```nginx
http {
    pow_gate_state_file /var/lib/nginx/pow_gate.state;
}
```

Without it (and without Redis) every visitor solves again after a full
restart. With it, only challenges that were still open during the restart are
refused once.
