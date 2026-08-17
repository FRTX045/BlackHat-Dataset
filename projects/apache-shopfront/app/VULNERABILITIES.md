# Planted weaknesses in the Fettle & Co shopfront

This application is **deliberately vulnerable**. It exists to be attacked by
this repository's build process and by nothing else. It publishes no host port,
it is reachable only from the three lab Docker networks, and every credential
in it is invented. Do not deploy it anywhere reachable.

This file is the reason the dataset can be trusted. For every weakness it
records where it is, why it works, the request that exploits it, and — the part
that actually matters for a log dataset — **what a successful exploit looks like
in the access log, and how it differs from a failed attempt**.

Every row has a test in `tests/app/test_vulnerabilities.py` asserting the
successful exploit, and where there is a hardened equivalent, a test asserting
that one refuses. Those tests are also how we know the weaknesses still work: a
refactor that accidentally fixed one would leave the Phase E playbooks producing
traffic labelled `exploitation` that never exploited anything, and nothing else
would notice.

**The byte counts below were measured, not estimated.** They come from a real
run against the container; the client address in a real dataset will differ, the
sizes will not by much. Every figure here was re-measured after the application
was resized to serve a realistic amount of markup, so they are the current ones
rather than the ones a smaller application used to produce.

> **Error pages are not compressed, and successful pages are.** `mod_deflate`
> is enabled and applies to `text/html`, but Apache does not run the output
> filter over an `ErrorDocument` response. So a `404` here is **7427** bytes on
> the wire while the home page — which is larger uncompressed, 27,277 bytes —
> goes out as 4028.
>
> That is real Apache behaviour with Debian's stock `deflate.conf`, not
> something arranged for effect, and it has a consequence worth knowing before
> reading any table below: **on this server a failed request is often bigger in
> `%b` than a successful one.** Any rule of the form "large response means data
> came back" is wrong here, and it is wrong on a great many real servers for
> exactly this reason.

---

## 1. SQL injection — `GET /search?q=`

**Where:** `app/search.php`. The search term is concatenated straight into the
statement. Every other query in the application uses prepared statements; this
endpoint is the documented exception.

**Exploit:**

```
GET /search?q=' UNION SELECT 1,2,3,username,password_hash,6,7,8 FROM users--
```

The products table has eight columns, so an eight-column `UNION` succeeds and
the username lands in the column the template renders as a product name.

**In the log:**

| Outcome | Status | `%b` |
|---|---|---|
| Successful `UNION` extraction | `200` | **3808** |
| Ordinary search (`q=oak`) | `200` | 3118 |

A successful extraction is about **22% larger** than an ordinary search page,
because it returns the injected rows on top of the matches. That is a much
narrower margin than it used to be, and the reason is worth knowing: the page
now carries a realistic amount of surrounding markup — navigation, footer,
structured data — so the injected rows are a smaller fraction of the whole.

**This is the realistic case, and it is harder.** On a page that was mostly
results, extraction doubled the byte count and stood out. On a page built like
a real storefront it does not, and response size alone is a weak signal. The
payload is still plainly visible in `%r`, which is what actually catches it.

**Boolean-blind:** `zzqq' OR 1=1--` and `zzqq' OR 1=2--` return different page
sizes. The term must be one that matches nothing on its own — a bare quote
leaves `name LIKE '%'`, which is true for every row, and both branches come back
identical.

**Time-based:** SQLite has no `SLEEP()`. The substitution is a query heavy
enough to take real time:

```
GET /search?q=' AND 1=(SELECT LENGTH(HEX(RANDOMBLOB(200000000))))--
```

Measured in the container: **~1.0s** against ~0.03s for the same query without
it. A three-way cross join does *not* work — SQLite optimises it away in 28ms.
Note this payload materialises a 400MB hex string, so the playbooks use it
sparingly.

**Hardened counterpart:** `/api/autocomplete` takes the same payload through a
prepared statement and answers `200` with `41` bytes of empty JSON.

---

## 2. Insecure direct object reference — `GET /account/orders/<id>`

**Where:** `app/account/order.php`. The lookup requires a session but never
checks the order belongs to it. Order ids are sequential integers **interleaved
across customers**, so the ids between one customer's own orders belong to
somebody else.

**Exploit:** sign in as `demo` (who owns orders 1, 5, 9, 13) and request order
2, which belongs to `rmarsh`.

**In the log:**

| Outcome | Status | `%b` |
|---|---|---|
| Someone else's order | `200` | 2427 |
| Your own order | `200` | 2397 |
| No such order | `404` | 7427 |

> **A successful IDOR is not distinguishable from a legitimate order view.**
> Same status, same order of magnitude in `%b`, same shape of URL. What gives it
> away is the *sequence*: a run of consecutive ids from one client, including
> ids that client does not own. Nothing in a single line reveals it. This is a
> genuine limitation of access-log detection and it is one of the more useful
> things in this dataset to practise on.

**Hardened counterpart:** `/account/addresses` performs the same shape of lookup
and stays scoped to the session user.

---

## 3. Path traversal — `GET /download?file=`

**Where:** `app/download.php`. The requested name is joined onto
`app/lib/docs/` with no normalisation and no check that the result stayed inside
that directory.

**Exploit:**

```
GET /download?file=../../../../../../../../etc/passwd
```

The documents live at `/var/www/html/lib/docs`, so reaching `/` takes five
levels. Attackers overshoot deliberately — traversing past root is harmless and
saves counting.

**In the log:**

| Outcome | Status | `%b` |
|---|---|---|
| `/etc/passwd` read | `200` | **327** |
| Legitimate document | `200` | 163 |
| Traversal that resolved to nothing | `404` | 7427 |

A `200` on a `/download` request whose `file` parameter contains `../` is
unambiguous, and the `327` is a recognisable fingerprint for `/etc/passwd` on
this image. A failed traversal falls to the `404` page, which is *larger* than
the successful read — worth knowing, because size alone points the wrong way.

---

## 4. Server-side request forgery — `GET /admin/import-image?url=`

**Where:** `app/admin/import-image.php`. The URL is taken from the caller and
fetched server-side with no restriction on scheme or host. It is also **not**
behind the admin role check, so any signed-in customer who finds it can use it.

**Exploit:**

```
GET /admin/import-image?url=http://169.254.169.254/latest/meta-data/
GET /admin/import-image?url=http://203.0.113.2/robots.txt
```

**In the log:**

| Outcome | Status | `%b` |
|---|---|---|
| Target reachable | `200` | 2341 |
| Target unroutable (cloud metadata) | `504` | 7559 |

> **A successful SSRF against a lab host leaves a second line.** When the target
> is inside the lab, Apache logs the fetch it made of itself:
>
> ```
> 203.0.113.2 - - [...] "GET /robots.txt HTTP/1.1" 200 152 "-" "FettleImporter/1.0"
> ```
>
> A request appearing to originate from the web container's own address, with
> the importer's user agent, is the tell. That correlation — attacker request in,
> server-originated request out — is the most reliably detectable thing in this
> whole file.

Nothing here can reach outside the lab: the container has no route off the three
lab networks, so an external or metadata target fails at the network layer. The
**attempt** is what lands in the dataset, which is the part an analyst has to
learn to recognise.

---

## 5. Upload bypass ending in a webshell — `POST /account/avatar`

**Where:** `app/account/avatar.php` and the `<Directory /var/www/html/uploads>`
block in `server/vhost.conf`. Two bugs compound, which is how this happens in
the wild:

1. The extension check looks only at the **last** extension, so `shell.php.jpg`
   passes.
2. The file keeps its **original name** instead of being renamed, so the `.php`
   in the middle survives.
3. The vhost applies `AddHandler application/x-httpd-php .php` to the uploads
   directory. The stock config uses a `FilesMatch` anchored to the end of the
   name, so only real `.php` files run; `AddHandler` goes through `mod_mime`,
   which treats a name as a *list* of extensions and runs anything with `.php`
   anywhere among them.

**Exploit:** upload `shell.php.jpg` containing PHP, then request it.

**In the log:**

| Outcome | Status | `%b` |
|---|---|---|
| Upload accepted | `POST … 200` | 2366 |
| Webshell executed | `GET /uploads/shell.php.jpg?cmd=id` `200` | **62** |
| Plain `.php` upload refused | `POST … 415` | 2315 |

The webshell request is the clearest signal in this document: a `200` on a
`/uploads/` path with a query string, returning **tens of bytes** where an
actual avatar would return tens of kilobytes. The `POST … 415` is what a
less careful attempt looks like.

---

## 6. Command injection — `GET /admin/ping?host=`

**Where:** `app/admin/ping.php`. The host is interpolated into a `shell_exec`
with no quoting, so a semicolon appends a second command. Not behind the admin
role check.

**Exploit:** `GET /admin/ping?host=127.0.0.1;id`

**In the log:**

| Outcome | Status | `%b` |
|---|---|---|
| Injected command ran | `200` | 2319 |
| Ordinary host check | `200` | 2308 |

> **11 bytes apart.** The response size is effectively useless for detection
> here — the injected `id` output is a few dozen characters inside a page that
> is otherwise identical. Only the payload in `%r` reveals it.

---

## 7. Server-side template injection — `GET /admin/template?tpl=`

**Where:** `app/admin/template.php`. A `{{ }}` expression is passed to `eval`
rather than looked up in a table of values. Not behind the admin role check.

**Exploit:** `GET /admin/template?tpl={{7*7}}`

**In the log:**

| Outcome | Status | `%b` |
|---|---|---|
| Expression evaluated (`49`) | `200` | 2306 |
| Ordinary template | `200` | 2299 |

> **One byte apart, and the exploit is the *smaller* one.** There is no
> size-based signal at all. This is the least detectable weakness in the
> application from the access log alone, and `%r` is the only evidence.

---

## 8. Cross-site scripting — `/search` and `/contact`

**Where:** `app/search.php` echoes the search term unescaped in one place.

**Exploit:** `GET /search?q=<script>alert(1)</script>` → `200`, 2289 bytes.

> **Barely visible in an access log, and stored XSS is invisible.** The
> reflected payload appears in `%r` and that is all. Retrieval of a stored
> payload is a request for an ordinary page and is **indistinguishable from
> normal browsing** — there is no line in the log that differs in any way.
>
> This is stated as a labelling limitation rather than pretended to be
> detectable. Truth records for stored-XSS retrieval are labelled by what the
> request *was*, not by what the response contained, because the access log
> contains no evidence of the latter.

---

## Hardened, so failed attacks land in the data too

A dataset where every attack succeeds teaches something false. These exist to
give attack traffic somewhere to fail:

| Control | Behaviour |
|---|---|
| `/api/autocomplete`, `/api/stock`, `/api/cart` | Prepared statements. The `UNION` payload returns `200` with 41 bytes of empty JSON. |
| `/account/addresses` | Scoped to the session user — same lookup shape as the IDOR, still correct. |
| `/admin/users`, `/admin/orders` | Role check enforced. An ordinary customer gets `403`, 371 bytes. |
| `/login` | Lockout after five failures, answering `429`. A brute-force run is visibly rate-limited in the status column, not merely unsuccessful. |
| Password storage | `password_hash` with bcrypt. |

---

## What is deliberately *not* here

- No weakness reachable without the application running in its lab network.
- No real credential, no real personal data, no third-party service.
- No path from this application to any host outside the three lab networks.
