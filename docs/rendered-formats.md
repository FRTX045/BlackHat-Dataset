# Rendered formats: the rules

**Status: agreed with the LogarX session on 2026-10-27**; the decisions are at
the end.

Every file this produces is **rendered from the Apache capture**. It is never a
capture. No nginx, IIS, Envoy, HAProxy or CDN served this traffic: each file is
Apache 2.4 + PHP's responses written in another server's columns, so that one
detector can be run on the same traffic in many formats and its results
compared. The traffic is held fixed; only the format varies.

## Inputs

Per tier (2026-10-06-small first, then medium):

- `access.log` and `truth.jsonl` — what ships, after the timestamp remap.
- `access.raw.log`, `truth.raw.jsonl` and `access.tagged.log` — the capture.
  The remap is re-run in memory on these with the manifest's seed, start and
  duration (verified byte-identical to the shipped files on all three tiers).
  That gives each shipped line two things the shipped line cannot carry:
  - its **modelled sub-second time**, which the remap computes and then
    truncates to whole seconds;
  - its **request id** — the `X-Request-Id` Apache logged in the tagged file,
    carried through the remap's reordering. 32 hex digits, e.g.
    `95ec4fa14ae91a124df1a176da634f8e`.

## What is measured, and what is not

**Measured** (taken from the shipped line, or the capture behind it): client
address, `%l`, `%u`, the whole-second time, the request line (method, target,
protocol), final status, response **body** size (`%b`, `-` when no body),
Referer, User-Agent, request id.

**Not measured by anything in the capture**, and so never written as if it
were:

| Quantity | Formats that want it |
|---|---|
| request or response size **including headers** | Apache `%I`/`%O`, HAProxy `%B`, ALB `received_bytes`/`sent_bytes`, GCP `requestSize`/`responseSize`, IIS `sc-bytes`/`cs-bytes`, CloudFront `sc-bytes`/`cs-bytes`, Cloudflare `EdgeResponseBytes` |
| durations and timers | nginx `$request_time`, ingress-nginx `$upstream_response_time`, Traefik duration, Caddy `duration`, Envoy/Istio `DURATION`, HAProxy `TR/Tw/Tc/Tr/Ta`, ALB processing times, IIS/CloudFront `time-taken`, GCP `latency` |
| the client's source port | HAProxy, ALB, Istio, Caddy, Traefik JSON |
| the `Host` header | Caddy, Traefik, Cloudflare, GCP, ECS, CloudFront `x-host-header` |
| anything about a proxy, CDN or TLS layer | upstream addresses, edge locations, cache results, ciphers, ARNs, ray ids |

The sub-second part of the time is **modelled**, not measured: it is the
remap's draw, already disclosed as inference in every remapped dataset.

## Rules that apply to every format

1. **Records 1:1.** Line N of a rendered file is line N of `access.log`, plus
   the format's header lines. Its truth file is `truth.jsonl` with `line_no`
   shifted by the header size: **+4 for IIS** (`#Software`, `#Version`, `#Date`,
   `#Fields`), **+2 for CloudFront** (`#Version`, `#Fields`), +0 for everything
   else. LogarX counts physical lines, so the offset is what keeps
   evidence pointing at the right line. One file per format, one header block
   at the top.
2. **Constants are declared.** A field nobody measured gets one fixed value
   for the whole file, the value the server writes for "unknown" where it has
   one (`-`, `-1`), and the constant is listed below and in the manifest. No
   field is filled with a random or modelled number. As agreed:
   where a format's byte field includes headers, the measured body size goes
   in it and the field is flagged as a **lower bound** (see Decisions).
3. **Escaping is re-done, not copied.** The Apache line's own escapes
   (`\"`, `\\`, `\xhh`, C-style whitespace; [mod_log_config][apache-log])
   are undone to the raw bytes, then the target server's escaping is applied.
   Measured: no line in the three 2026-10-06 tiers contains an Apache escape
   or a non-ASCII byte, so on this traffic the only escaping that ever fires
   is a format's own (IIS `+` for space, CloudFront `%20`, Traefik JSON
   `&`). Implemented anyway, and tested on constructed inputs.
4. **Times are UTC.** Every shipped line is `+0000`. Text formats that write
   whole seconds keep the shipped second exactly. Formats with sub-second
   times write the remap's modelled time, whose whole second is always the
   shipped one.
5. **Host is `shop.test`, port 80, scheme `http`** wherever a format asks for
   them: the application's only vhost, served over plain HTTP. Per request the
   Host header was not recorded, so this is a constant. Requests the noise
   client sent with no Host header at all get it too, which is wrong for those
   few lines and cannot be fixed from the capture.
6. **Upstream and proxy addresses are fixed RFC 1918 constants**
   (`10.0.0.20:80` for "the server", `10.0.0.10` for a proxy's own address),
   never a lab container's address: those are what `verify.py` refuses to see
   in content.
7. **Malformed request lines** (94 / 294 / 910 lines: `GARBAGE`,
   `GET /.env x`, a bare `GET /backup.zip`) stay, 1:1, and are counted per
   format. Several of these servers would not have logged them in this form —
   see each format's *Malformed* row — and that is said in the manifest rather
   than hidden by dropping lines, which would break the 1:1 truth.

## Per format

Each block: the layout written, where each field comes from, the escaping,
the constants, and the source the layout and escaping were checked against.
LogarX's `builtins.py` and its samples were used for field placement only.

### Apache family

Source for all four: [mod_log_config][apache-log]; Debian's stock formats as
read from this build's own image, `/etc/apache2/apache2.conf` lines 212–214.

| Format | Layout | Notes |
|---|---|---|
| `apache-common` | `%h %l %u %t "%r" %>s %b` | Exact: the shipped line minus Referer and User-Agent. |
| `apache-vhost-common` | `%v %h %l %u %t "%r" %>s %b` | `%v` = `shop.test`, the canonical ServerName ([docs' own `vhost_common`][apache-log]). Exact. |
| `apache-vhost-combined` | `%v:%p %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"` | `shop.test:80`. **Debian's stock `vhost_combined` uses `%O`, not `%b`**; this is written with `%b`, as this server redefines `combined`, and as LogarX defines it. Exact under that redefinition. |
| `apache-combined-io` | combined + ` %I %O` | Both counts unmeasured: `%I` the request-size lower bound, `%O` the body size, both flagged as lower bounds (Decisions 1 and 2). |

Escaping: Apache's own, so the shipped bytes carry over unchanged.

### nginx family

Source: [ngx_http_log_module][nginx-log] (the `combined` definition, `escape`);
[ngx_http_log_module.c][nginx-src] (`ngx_http_log_escape`: bytes 0x00–0x1F,
`"`, `\`, 0x7F and 0x80–0xFF become `\xXX`; a variable not found is `-`);
[ingress-nginx log format][ingress-log].

| Format | Layout | Fields beyond combined |
|---|---|---|
| `nginx-main` | combined + ` "$http_x_forwarded_for"` | XFF `-`: the client connects directly, so `$remote_addr` is the client and no proxy added a header. |
| `nginx-combined-forwarded` | combined + ` "$http_x_forwarded_for" $request_time` | XFF `-` as above. `$request_time` **constant `0.000`** (unmeasured). |
| `ingress-nginx` | `upstreaminfo`: combined + ` $request_length $request_time [$proxy_upstream_name] [$proxy_alternative_upstream_name] $upstream_addr $upstream_response_length $upstream_response_time $upstream_status $req_id` | `$req_id` = the **measured** request id (nginx's own `$request_id` is the same 32-hex shape). `$upstream_status` = the status. `$upstream_response_length` = `%b` body size, `0` for `-`. `$request_length` **unmeasured** (includes headers): a lower bound (Decisions). `$request_time`, `$upstream_response_time` constant `0.000`. Upstream `[default-shop-80]`, alternative `[]`, `$upstream_addr` `10.0.0.20:80`. |

`$body_bytes_sent` is `0` where Apache wrote `-`: nginx counts, it never
writes `-` for this variable. Escaping: nginx default (`\x22` for `"`, not
Apache's `\"`). Time: `$time_local`, the shipped stamp.

*Malformed:* nginx answers these with 400 and logs the request text as
received. Kept as is.

### Traefik

Sources: [Traefik access logs][traefik-log] (field meanings, CLF layout,
`defaultMode` drop); [logger_formatters.go][traefik-clf] (CLF writer); LogarX's
sample written by Traefik 3.7.16 (`&` for `&` in `RequestPath`).

| Format | Layout and fields |
|---|---|
| `traefik-common` | `%h - - [StartUTC] "METHOD path PROTO" status size "Referer" "User-Agent" RequestCount "router" "service_url" Nms`. Time is `StartUTC` in `02/Jan/2006:15:04:05 -0700`, so `+0000`. Path, method and protocol are written **unescaped**; only `"` inside Referer and User-Agent becomes `\"`. Missing Referer/UA are `"-"`. `RequestCount` = position in the file (Traefik's "requests received since start"). Router `"shop@file"`, service URL `"http://10.0.0.20:80"`, duration **constant `0ms`**. |
| `traefik-json` | `ClientAddr`, `ClientHost`, `ClientPort`, `DownstreamStatus`, `DownstreamContentSize`, `OriginStatus`, `OriginContentSize`, `RequestHost`, `RequestMethod`, `RequestPath` (**query included**), `RequestProtocol`, `RequestScheme`, `RequestCount`, `RouterName`, `ServiceURL`, `StartUTC` (RFC 3339, nanoseconds, from the modelled time), `Duration` constant `0`, `request_Referer`, `request_User-Agent`, `level`, `msg`, `time`. Go `encoding/json`, so `&`, `<`, `>` become `&`, `<`, `>`. |

Headers: Traefik's default drops request headers, which would leave Referer
and User-Agent `"-"` on every line. These files are written as a Traefik
configured to **keep** `User-Agent` and `Referer`
(`accesslog.fields.headers.names.User-Agent=keep`). That is a real
configuration, and without it the comparison loses the two fields detection
reads most. `ClientPort` is unmeasured: constant `0`; `ClientAddr` is
`client:0`.

*Malformed:* Go's HTTP server answers a request it cannot read with a bare
`400 Bad Request` from `conn.serve` and returns before any handler runs
([net/http server.go][go-server]), so a real Traefik would have no access-log
line for `GARBAGE` or `GET /.env x`. Kept, counted, flagged.

### JSON formats

| Format | Fields written | Source |
|---|---|---|
| `nginx-json` | `time_local`, `remote_addr`, `request`, `status`, `body_bytes_sent`, `http_referer`, `http_user_agent`, all as JSON strings, `log_format ... escape=json`. **An absent Referer is `""`, not `"-"`**: with `escape=json` nginx writes nothing for a variable not found. `body_bytes_sent` `"0"` for `-`. | [nginx-log], [nginx-src] (`ngx_http_log_json_variable`) |
| `caddy-json` | `level`, `ts` (Unix seconds, float, modelled time), `logger` `http.log.access.log0`, `msg` `handled request`, `request` {`remote_ip`, `remote_port` constant `"0"`, `client_ip`, `proto`, `method`, `host` `shop.test`, `uri` (**path and query**), `headers` {`User-Agent`: [..], `Referer`: [..]}: **header values are arrays**, absent headers are left out}, `bytes_read` `0`, `user_id` `""`, `duration` constant `0`, `size` (body, `0` for `-`), `status`, `resp_headers` `{}`. | [Caddy log directive][caddy-log] (`unix_seconds_float`, duration in seconds, headers as string arrays); LogarX's sample written by Caddy 2.11.7 |
| `cloudflare-json` | `ClientIP`, `ClientRequestHost`, `ClientRequestMethod`, `ClientRequestURI` (**path and query**), `ClientRequestPath`, `ClientRequestProtocol`, `ClientRequestReferer`, `ClientRequestUserAgent`, `EdgeResponseStatus`, `EdgeStartTimestamp` (**`unixnano`**, the API default, from the modelled time), `RayID` (from the request id, 16 hex). `EdgeResponseBytes`: a lower bound (Decisions). | [Logpush http_requests fields][cf-fields], [Logpush output options][cf-output] |
| `gcp-http-json` | `timestamp` (RFC 3339, `Z`, microseconds, modelled), `httpRequest` {`requestMethod`, `requestUrl` = **`http://shop.test` + path + query**, `status` (integer), `userAgent`, `remoteIp`, `referer`, `protocol`}. `responseSize` and `requestSize` are **strings** and include headers: left out (they are optional); `latency` left out. Fields absent from the request are omitted, not `"-"`. | [LogEntry / HttpRequest][gcp-logentry] |
| `ecs-http` | `@timestamp` (RFC 3339, milliseconds, modelled), `client.ip`, `source.ip`, `http.request.method` (case as received), `http.request.referrer`, `http.version`, `http.response.status_code`, `http.response.body.bytes` (`%b`; omitted when Apache wrote `-`), `url.original` (target as received), `url.path`, `url.query` (**without the `?`**; absent when the target has no `?`, empty string when it ends in `?`), `url.domain` `shop.test`, `user_agent.original`. Nested objects, as Filebeat writes them. | [ECS http][ecs-http], [ECS url][ecs-url] |

*Malformed:* for formats that split method and path, `GARBAGE` is written as
method `GARBAGE` with an empty path; `GET /.env x` as method `GET`, target
`/.env`, protocol `x`; `GET /backup.zip` with no protocol. Caddy would not
have logged these at all (Go rejects them, as for Traefik). What Cloudflare and
Google's load balancer log for a request line they cannot parse is not
documented in the pages cited here. Kept, counted, flagged.

### Column formats

**`iis-w3c`.** Header block:

```
#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Date: <first record's date> <first record's time>
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
```

These are IIS's default fields (`logExtFileFlags` default: Date, Time,
ClientIP, UserName, ServerIP, Method, UriStem, UriQuery, TimeTaken,
HttpStatus, Win32Status, ServerPort, UserAgent, HttpSubStatus, Referer —
**Referer has been a default since IIS 8.0**, so the default *does* carry
both Referer and User-Agent). Field order as IIS writes them. `date`/`time`
UTC, whole seconds. `cs-uri-query` without the `?`, `-` when there is none.
`-` for every empty field. **Spaces and non-printable characters become `+`**
(Microsoft's own example: `Mozilla/4.0+(compatible;MSIE+5.5;+Windows+2000+Server)`).
`s-ip` `10.0.0.20`, `s-port` `80`, `cs-username` `-` (Apache's `%u` is `-` on
every line), `sc-substatus` `0`, `sc-win32-status` `0`, `time-taken` constant
`0`. `sc-bytes`/`cs-bytes` are not in the default set (the February 2026
update adds them by default on some Windows versions) and are not written.
Sources: [IIS logFile defaults][iis-logfile], [HTTP Server API W3C
logging][w3c-logging].

*Malformed:* HTTP.sys rejects a request it cannot parse itself and records it
in its own HTTPERR log, not the site's W3C log ([HTTP.sys error log
files][httperr]). Kept, counted, flagged.

**`cloudfront`.** Header block: `#Version: 1.0` and the 33-field `#Fields:`
line exactly as AWS documents it, tab-separated. `date`/`time` UTC, whole
seconds. **URL-encoding** of every value per AWS's list: bytes 0–32 and
127+, and `< > " # % { } | \ ^ ~ [ ] ` ' ` and space. That includes **`%`, so a
query the client had already encoded is encoded again** (`%27` becomes
`%2527`): CloudFront does this, and it is the most likely place for a reader
to go wrong. `cs-uri-stem` and `cs-uri-query` without the `?`, `-` when empty.
`cs(Host)` is the distribution's domain, constant `d111111abcdef8.cloudfront.net`
(AWS's example); `x-host-header` `shop.test`. Constants: `x-edge-location`
`LAX1`, `x-edge-result-type`/`x-edge-response-result-type`/`x-edge-detailed-result-type`
`Miss` (`Error` for 4xx/5xx, per AWS's definition), `cs-protocol` `http`,
`ssl-*` `-`, `x-forwarded-for` `-`, `fle-*` `-`, `time-taken` and
`time-to-first-byte` `0.000`, `c-port` `0`, `x-edge-request-id` from the
request id. `sc-bytes`/`cs-bytes`: a lower bound (Decisions). `sc-content-type`,
`sc-content-len`, range fields `-`. Sources: [CloudFront standard logs
reference][cf-std] (fields, order, example), [archived CloudFront guide][cf-encoding]
(the URL-encoding list, which the current page no longer carries).

*Malformed:* what CloudFront logs for a request line it cannot parse is not in
AWS's pages (they cover only over-size requests, which are not logged). Kept
as received, flagged `kept_as_received`.

### Proxies

None has header lines. Sources: [HAProxy 3.2 configuration manual][haproxy]
§8.2.3 (`option httplog`), §8.6 (non-printable characters), §8.8 and §4.2
`capture request header`, `log ... len`; [Envoy access log usage][envoy-usage]
and [substitution formatter][envoy-fmt]; [Istio access logs][istio-log];
[ALB access log entries][alb]. The HAProxy, Envoy and Istio layouts also match
the lines HAProxy 3.2.26 and Envoy 1.36.13 wrote in Docker on 2026-10-25.

**`haproxy`.** `option httplog`, `log stdout len 8192 format raw`, with
`capture request header Referer len 4096` and `capture request header
User-Agent len 4096`, in that order:

```
<client>:<port> [<tr>] http-in shop/web1 0/0/0/0/0 <status> <bytes> - - ---- 1/1/0/0/0 0/0 {<Referer>|<User-Agent>} "<request line>"
```

`%tr` is the request date, **local time, milliseconds, no zone**; the
rendered HAProxy runs in UTC, so it is the modelled time to the millisecond.
Escaping: `#XX` for bytes outside 32–126, for `#` itself (`#23`) and `"`
(`#22`); inside the capture block also `{`, `|`, `}`. Spaces are **not**
encoded in headers. A header the request lacked is an empty string in its
slot (`{|curl/8.4.0}`). Without the two captures HAProxy logs no Referer or
User-Agent at all; with them, a real configuration. `len 8192` because
HAProxy's default 1024-byte line cuts long attack queries. Timers constant
`0/0/0/0/0`, connection counts `1/1/0/0/0`, queues `0/0`, termination state
`----`, cookies `- -`, port constant `0`. `%B` includes headers: see Open
decisions. *Malformed:* HAProxy logs an invalid request as `"<BADREQ>"`, not
the bytes sent; the manual's own example (§8.2 `log-profile`, line 27409 of
the 3.2.0 text) is `myproxy/<NOSRV> -1/-1/-1/-1/384 400 0 - - CR-- ...
"<BADREQ>"`. These are rendered as HAProxy would, following that
example: server `<NOSRV>`, timers `-1/-1/-1/-1/0`, status `400`, bytes `0`,
`CR--`. The attack content of those lines is lost, which is also what a real
HAProxy log loses.

**`envoy`.** The default format, edge proxy with `use_remote_address: true`:

```
[<START_TIME>] "<METHOD> <PATH> <PROTOCOL>" <status> - <BYTES_RECEIVED> <BYTES_SENT> <DURATION> <upstream-time> "<XFF>" "<User-Agent>" "<request-id>" "<authority>" "<upstream-host>"
```

`START_TIME` UTC, milliseconds, `Z` (as in Envoy's own example). XFF is the
client address: the edge appends the peer's address and these clients sent
none. `BYTES_SENT` is **body** bytes ([formatter][envoy-fmt]: "the size of the
response body"), so `%b` maps to it exactly, `0` for `-`. `BYTES_RECEIVED`
request body bytes: `0` for GET/HEAD, unmeasured for POST — constant `0`.
`DURATION` and `x-envoy-upstream-service-time` constant `0`. Response flags
`-`. Request id: an edge Envoy replaces an incoming `x-request-id` with its
own UUID, so the measured id is written in UUID layout (8-4-4-4-12). Authority
`shop.test`, upstream `10.0.0.20:80`. **No escaping**: Envoy writes header
values as they came. Measured: no User-Agent in the three tiers contains `"`,
so no line is affected by LogarX's refusal of ambiguous quotes. No Referer
field. *Malformed:* Envoy's codec rejects these before routing and logs
`"- - HTTP/1.1" 400 DPE` (as in LogarX's own `refused` capture). Rendered as
that capture, field for field: `[<time>] "- - HTTP/1.1" 400 DPE 0 11 0 - "-"
"-" "-" "-" "-"`.

**`istio`.** Istio's default `EnvoyTextLogFormat`, the layout above plus
`RESPONSE_CODE_DETAILS` `via_upstream`, `CONNECTION_TERMINATION_DETAILS` `-`,
`"UPSTREAM_TRANSPORT_FAILURE_REASON"` `"-"`, and at the end
`UPSTREAM_CLUSTER_RAW` `inbound|80||`, `UPSTREAM_LOCAL_ADDRESS`
`127.0.0.6:0`, `DOWNSTREAM_LOCAL_ADDRESS` `10.0.0.20:80`,
`DOWNSTREAM_REMOTE_ADDRESS` = **client:port** (port constant `0`, unmeasured),
`REQUESTED_SERVER_NAME` `-`, `ROUTE_NAME` `default`. Same escaping (none),
same constants, same malformed rule as Envoy.

**`aws-alb`.** The 36 fields in AWS's order, from AWS's HTTP example:

```
http <time> app/shop-alb/50dc6c495c0c9188 <client>:<port> 10.0.0.20:80 0.000 0.000 0.000 <status> <status> <received> <sent> "<METHOD> http://shop.test:80<target> <PROTO>" "<User-Agent>" - - arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/shop/73e2d6bc24d8a067 "Root=1-..." "-" "-" 0 <request_creation_time> "forward" "-" "-" "10.0.0.20:80" "<status>" "-" "-" TID_<id> "-" "-" "-" - - -
```

`request_creation_time` is the modelled time (ISO 8601, microseconds, `Z`);
`time` (when the response was sent) is the same instant, since no duration was
measured. The request is a **whole URL**, `http://shop.test:80` + target. User
Agent quoted as received (AWS documents no escaping; it truncates over 8 KB,
which no line here reaches). No Referer field. Processing times constant
`0.000`. Trace id from the request id. Port constant `0`. `received_bytes` and
`sent_bytes` include headers: a lower bound (Decisions). *Malformed:* ALB documents
that malformed requests are still logged, with `-1` processing times and `-`
target: written that way, which is faithful.

## Decisions (agreed with the LogarX session, 2026-10-27)

1. **Byte fields that include headers** carry the measured body size, and the
   manifest names each such field as a lower bound (`lower_bound_fields`):
   HAProxy `%B`, ALB `sent_bytes`/`received_bytes`, CloudFront
   `sc-bytes`/`cs-bytes`, Cloudflare `EdgeResponseBytes`, ingress-nginx
   `$request_length`, Apache `%I`/`%O`.
   A **request** size is bounded below by what the capture holds: the
   request line, the Referer and User-Agent headers when sent, each with its
   CRLF, and the closing blank line. Everything else the client sent was
   never recorded.
2. **`apache-combined-io` is rendered**, `%I` and `%O` both lower bounds as
   above. What it tests is whether a detector picks combined-io for the file
   rather than reading it as combined with junk on the end.
3. **Malformed lines** are written as the server writes them where a source
   or a capture shows it (HAProxy `<BADREQ>`; Envoy and Istio as the
   2026-10-25 Envoy 1.36.13 refusal, every request field `-`, `BYTES_SENT`
   `11` as captured, `DURATION` `0`). Istio keeps `DOWNSTREAM_REMOTE_ADDRESS`
   as `client:0` on those lines: the formatter defines it as the "remote
   address of the downstream connection", a property of the connection, which
   existed. Where the server would not have logged the line at all (Caddy,
   Traefik, IIS) it is kept and flagged so. Where nothing cited says, it is
   kept as received and flagged as that.
4. **Header-keeping configurations** as written above: Traefik keeps
   User-Agent and Referer; HAProxy captures Referer then User-Agent. LogarX's
   built-in `haproxy` does not read the capture block as either header, by
   design, since which slot holds which is configuration.

## Flags

Every line a server would have written differently is named in
`rendered/MANIFEST.json`, per format, by its **physical line number** in that
file (header lines counted, as LogarX counts them):

| Flag | Means |
|---|---|
| `rendered_as_server_rejects` | written as that server writes its refusal, not as Apache received it |
| `server_would_not_log` | that server would not have written this line at all: a request line it rejects before logging, or one of Apache's own dummy connections (`127.0.0.1 "OPTIONS * HTTP/1.0"`), which only Apache writes |
| `kept_as_received` | a malformed request line written as received, where the server's handling is not documented in the sources cited |

The malformed request lines are those that are not `METHOD TARGET HTTP/x.y`:
94 / 294 / 910 lines in the 2026-10-06 small / medium / large tiers, every one
from the noise client 203.0.113.6.

## Output

`datasets/apache-shopfront/<build>/rendered/<format>.log` and
`<format>.truth.jsonl`, a `MANIFEST.json` naming every offset, lower-bound
field and flagged line, and a `SHA256SUMS`. Not committed, like every full
log. Written by `python3 tools/render.py <build>`, which re-runs the remap and
refuses unless that reproduces the shipped log exactly. Each file's first
mention anywhere says "rendered from the Apache capture".

[apache-log]: https://httpd.apache.org/docs/2.4/mod/mod_log_config.html
[nginx-log]: https://nginx.org/en/docs/http/ngx_http_log_module.html
[nginx-src]: https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_log_module.c
[ingress-log]: https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/log-format/
[traefik-log]: https://doc.traefik.io/traefik/reference/install-configuration/observability/logs-and-accesslogs/
[traefik-clf]: https://github.com/traefik/traefik/blob/master/pkg/middlewares/accesslog/logger_formatters.go
[caddy-log]: https://caddyserver.com/docs/caddyfile/directives/log
[cf-fields]: https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/zone/http_requests/
[cf-output]: https://developers.cloudflare.com/logs/logpush/logpush-job/log-output-options/
[gcp-logentry]: https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry
[ecs-http]: https://www.elastic.co/docs/reference/ecs/ecs-http
[ecs-url]: https://www.elastic.co/docs/reference/ecs/ecs-url
[iis-logfile]: https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/sitedefaults/logfile/
[w3c-logging]: https://learn.microsoft.com/en-us/windows/win32/http/w3c-logging
[cf-std]: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/standard-logs-reference.html
[cf-encoding]: https://github.com/awsdocs/amazon-cloudfront-developer-guide/blob/main/doc_source/AccessLogs.md
[haproxy]: https://docs.haproxy.org/3.2/configuration.html
[envoy-usage]: https://www.envoyproxy.io/docs/envoy/latest/configuration/observability/access_log/usage
[envoy-fmt]: https://www.envoyproxy.io/docs/envoy/latest/configuration/advanced/substitution_formatter
[istio-log]: https://istio.io/latest/docs/tasks/observability/logs/access-log/
[alb]: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
[go-server]: https://github.com/golang/go/blob/master/src/net/http/server.go
[httperr]: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc786081(v=ws.10)
