// afterburner-site Worker.
//
// Single Worker fronts https://afterburner.sh + https://www.afterburner.sh.
// Static assets in ../website are served via the Static Assets binding
// (env.ASSETS). The Worker only intervenes when behavior must differ from
// "send the file at this path":
//
//   GET / + curl/wget UA   -> install.sh   (text/x-shellscript)
//   GET / + PowerShell UA  -> install.ps1  (text/plain)
//   GET / + browser UA     -> index.html
//   GET /uninstall[/]      -> uninstall.sh / uninstall.ps1 by the same
//                             UA dispatch (browser UA -> docs.html)
//   GET /docs[/]           -> docs.html
//   everything else        -> ASSETS pass-through, with cache + security
//                             headers stamped by content-type.
//
// Override knobs: ?install=sh|ps1|html, or Accept: text/html for the
// HTML escape hatch when a curl-spoofed UA wants the marketing page.
//
// Routing decisions are factored into the pure `planRoute` function so
// they can be unit-tested without spinning up the assets binding (which
// vitest-pool-workers 0.5.x can't run in worker-first mode anyway).

export interface Env {
  ASSETS: Fetcher;
}

const SH_RE = /^(?:curl|wget|fetch|httpie|aria2)\b/i;
const PS_RE = /(?:PowerShell|WindowsPowerShell|Invoke-WebRequest|pwsh)/i;

export const HEADERS_SECURITY = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
} as const;

// RFC 8288 agent discovery, stamped on HTML responses only (a shell script
// has nothing to describe). Both relation types are IANA-registered:
// `describedby` (POWDER) and `help` (HTML). There is deliberately no
// `rel="sitemap"` here - no such relation is registered, and the sitemap is
// advertised the standard way, via the `Sitemap:` directive in robots.txt.
export const LINK_AGENT = [
  '</llms.txt>; rel="describedby"; type="text/plain"',
  '</docs>; rel="help"; type="text/html"',
].join(", ");

export const CACHE = {
  HTML: "public, max-age=300",
  INSTALL: "public, max-age=60",
  CSS_JS: "public, max-age=86400",
  IMMUTABLE: "public, max-age=31536000, immutable",
} as const;

const RE_IMMUTABLE = /\.(?:png|jpg|jpeg|webp|svg|mp4|webm|woff2?)$/i;
const RE_CSS_JS = /\.(?:css|js|mjs)$/i;

/**
 * The header set for every HTML response, from whichever branch produced it.
 * Single definition so the apex, /docs and the escape hatch can never drift.
 */
export function htmlHeaders(): Record<string, string> {
  return {
    "content-type": "text/html; charset=utf-8",
    "cache-control": CACHE.HTML,
    link: LINK_AGENT,
    ...HEADERS_SECURITY,
  };
}

export type RoutePlan =
  // Fetch a different asset from ASSETS and stamp these response headers.
  | {
      kind: "rewrite";
      assetPath: string;
      headers: Record<string, string>;
    }
  // Pass the request through to ASSETS unchanged; on success, layer these
  // headers on top of whatever ASSETS returns.
  | {
      kind: "passthrough";
      headers: Record<string, string>;
    };

/**
 * Pure routing function: given a request, decide what to serve. Does
 * NOT touch I/O — testable as a synchronous function.
 */
export function planRoute(req: Request): RoutePlan {
  const url = new URL(req.url);
  const method = req.method;

  if (
    url.pathname === "/" &&
    (method === "GET" || method === "HEAD")
  ) {
    return planScripted(req, url, "/install.sh", "/install.ps1", "/index.html");
  }

  if (
    (url.pathname === "/uninstall" || url.pathname === "/uninstall/") &&
    (method === "GET" || method === "HEAD")
  ) {
    // Same UA dispatch as the apex; a browser landing here gets the
    // docs (which document uninstall), not the marketing page.
    return planScripted(req, url, "/uninstall.sh", "/uninstall.ps1", "/docs.html");
  }

  if (url.pathname === "/docs" || url.pathname === "/docs/") {
    return {
      kind: "rewrite",
      assetPath: "/docs.html",
      headers: htmlHeaders(),
    };
  }

  return {
    kind: "passthrough",
    headers: passthroughHeaders(url.pathname),
  };
}

function planScripted(
  req: Request,
  url: URL,
  shAsset: string,
  psAsset: string,
  htmlAsset: string,
): RoutePlan {
  const ua = req.headers.get("user-agent") ?? "";
  const accept = req.headers.get("accept") ?? "";
  const raw = url.searchParams.get("install");
  // Normalize: unknown values behave as if no override was given. Keeps
  // ?install=banana from disabling UA dispatch silently.
  const force =
    raw === "html" || raw === "sh" || raw === "ps1" ? raw : null;

  // Explicit ?install=html OR Accept: text/html (only when no override) → HTML.
  if (force === "html" || (force === null && accept.includes("text/html"))) {
    return {
      kind: "rewrite",
      assetPath: htmlAsset,
      headers: htmlHeaders(),
    };
  }

  if (force === "sh" || (force === null && SH_RE.test(ua))) {
    return {
      kind: "rewrite",
      assetPath: shAsset,
      headers: {
        "content-type": "text/x-shellscript; charset=utf-8",
        "cache-control": CACHE.INSTALL,
        ...HEADERS_SECURITY,
      },
    };
  }

  if (force === "ps1" || (force === null && PS_RE.test(ua))) {
    return {
      kind: "rewrite",
      assetPath: psAsset,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": CACHE.INSTALL,
        ...HEADERS_SECURITY,
      },
    };
  }

  return {
    kind: "rewrite",
    assetPath: htmlAsset,
    headers: htmlHeaders(),
  };
}

/**
 * Pure: decide which response headers to layer on top of an ASSETS
 * passthrough response, based on the URL path.
 */
export function passthroughHeaders(path: string): Record<string, string> {
  const out: Record<string, string> = { ...HEADERS_SECURITY };
  if (RE_IMMUTABLE.test(path)) {
    out["cache-control"] = CACHE.IMMUTABLE;
  } else if (RE_CSS_JS.test(path)) {
    out["cache-control"] = CACHE.CSS_JS;
  } else if (path === "/install.sh" || path === "/uninstall.sh") {
    out["cache-control"] = CACHE.INSTALL;
    out["content-type"] = "text/x-shellscript; charset=utf-8";
  } else if (path === "/install.ps1" || path === "/uninstall.ps1") {
    out["cache-control"] = CACHE.INSTALL;
    out["content-type"] = "text/plain; charset=utf-8";
  } else if (path.endsWith(".html")) {
    out["cache-control"] = CACHE.HTML;
    out["link"] = LINK_AGENT;
  }
  return out;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const plan = planRoute(req);

    if (plan.kind === "rewrite") {
      const url = new URL(req.url);
      const upstream = await env.ASSETS.fetch(
        new Request(new URL(plan.assetPath, url.origin), { method: "GET" }),
      );
      return overlay(upstream, plan.headers);
    }

    const upstream = await env.ASSETS.fetch(req);
    if (upstream.status < 200 || upstream.status >= 300) return upstream;
    return overlay(upstream, plan.headers);
  },
};

function overlay(res: Response, headers: Record<string, string>): Response {
  const h = new Headers(res.headers);
  for (const [k, v] of Object.entries(headers)) h.set(k, v);
  return new Response(res.body, { status: res.status, headers: h });
}
