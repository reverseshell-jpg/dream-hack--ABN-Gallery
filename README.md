# DreamHack: ABN Gallery
**Category:** Web Exploitation
**Difficulty:** Silver 1

## Overview

The challenge is a Node.js (Express) "gallery proxy" application vulnerable to **SSRF chained with Local File Inclusion (path traversal)**, enabled by a flawed private-IP filter. The flag is stored at `/flag` (mode `440`, readable by the `chall` user that runs the app).

## 1. Recon

### `GET /fetch?url=<url>`
- Logs every request to `/abn_gallery/logs/<timestamp>.json`.
- `extractHost()` extracts the hostname with raw string slicing (no proper URL parsing).
- `hostIsPublic()` validates the host using the `ip` npm package.
  - If the host is **not public** → `res.redirect(pathname + search)` (client-side redirect).
  - If the host **is public** → the server performs the upstream `fetch()` and pipes the response back to the client.

### `GET /admin?log=<file>`
- Only accessible when `ip.isPrivate(req.ip) === true`.
- Builds the file path with `path.join(LOG_DIR, log)` **without any sanitization** → direct path traversal.

## 2. Exploitation

Inspecting the `isPrivate` / `isPublic` functions in `node_modules/ip/lib/ip.js`:

<img width="708" height="604" alt="image" src="https://github.com/user-attachments/assets/a935f46f-a2ae-425f-803d-61401cbbc96d" />

`0.0.0.0` doesn't match **any** of the private-range patterns the library checks (`10.x`, `192.168.x`, `172.16-31.x`, `169.254.x`, loopback, link-local, etc.). As a result:

```js
ip.isPrivate("0.0.0.0") === false
ip.isPublic("0.0.0.0")  === true   // since isPublic = !isPrivate
```

This passes the SSRF filter on `/fetch`. On Linux, connecting to `0.0.0.0` as a **destination** is routed by the kernel to loopback (`127.0.0.1`). So when the server-side `fetch()` connects to `0.0.0.0:3000`, it's effectively talking to itself over `127.0.0.1`.

Because this is now a loopback connection, the inbound request that `/admin` receives has `req.ip === "127.0.0.1"` — which **does** match `isPrivate()` — satisfying the admin check and unlocking the log-reading endpoint. From there, the unsanitized `path.join(LOG_DIR, log)` allows traversal outside `LOG_DIR` to read arbitrary files, including `/flag`.

## 3. Get the Flag

```bash
curl "http://host3.dreamhack.games:21658/fetch?url=http://0.0.0.0:3000/admin?log=../../flag"
```
