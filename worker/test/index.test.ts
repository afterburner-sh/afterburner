import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  CACHE,
  HEADERS_SECURITY,
  LINK_AGENT,
  htmlHeaders,
  passthroughHeaders,
  planRoute,
} from "../src/index.js";

const APEX = "https://afterburner.sh";

const UA_CURL = "curl/8.7.1";
const UA_WGET = "Wget/1.21.4 (linux-gnu)";
const UA_HTTPIE = "HTTPie/3.2.2";
const UA_ARIA2 = "aria2/1.36.0";
const UA_FETCH = "fetch/0.5";
const UA_PS_CORE = "Mozilla/5.0 (Windows NT) PowerShell/7.4.1";
const UA_PS_WIN = "Mozilla/5.0 (Windows NT) WindowsPowerShell/5.1.19041.4291";
const UA_PS_IWR = "Mozilla/5.0 Invoke-WebRequest/5.1";
const UA_PWSH = "Mozilla/5.0 pwsh/7.5.0";
const UA_BROWSER =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/126.0";

function r(
  url: string,
  opts: { method?: string; ua?: string; accept?: string } = {},
): Request {
  const headers: Record<string, string> = {};
  if (opts.ua !== undefined) headers["user-agent"] = opts.ua;
  if (opts.accept !== undefined) headers["accept"] = opts.accept;
  return new Request(APEX + url, { method: opts.method ?? "GET", headers });
}

describe("planRoute — apex UA dispatch (script senders)", () => {
  it("curl/N rewrites to /install.sh with shellscript content-type", () => {
    const plan = planRoute(r("/", { ua: UA_CURL }));
    expect(plan).toEqual({
      kind: "rewrite",
      assetPath: "/install.sh",
      headers: expect.objectContaining({
        "content-type": "text/x-shellscript; charset=utf-8",
        "cache-control": CACHE.INSTALL,
      }),
    });
  });

  it("Wget UA rewrites to /install.sh", () => {
    expect(planRoute(r("/", { ua: UA_WGET }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/install.sh",
    });
  });

  it("HTTPie rewrites to /install.sh", () => {
    expect(planRoute(r("/", { ua: UA_HTTPIE }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/install.sh",
    });
  });

  it("aria2 rewrites to /install.sh", () => {
    expect(planRoute(r("/", { ua: UA_ARIA2 }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/install.sh",
    });
  });

  it("fetch UA rewrites to /install.sh", () => {
    expect(planRoute(r("/", { ua: UA_FETCH }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/install.sh",
    });
  });

  it("install.sh response cache-control is short (1 min)", () => {
    const plan = planRoute(r("/", { ua: UA_CURL }));
    if (plan.kind !== "rewrite") throw new Error("expected rewrite");
    expect(plan.headers["cache-control"]).toMatch(/max-age=60\b/);
  });
});

describe("planRoute — apex UA dispatch (PowerShell variants)", () => {
  it("PowerShell/N rewrites to /install.ps1 with text/plain", () => {
    const plan = planRoute(r("/", { ua: UA_PS_CORE }));
    expect(plan).toEqual({
      kind: "rewrite",
      assetPath: "/install.ps1",
      headers: expect.objectContaining({
        "content-type": "text/plain; charset=utf-8",
        "cache-control": CACHE.INSTALL,
      }),
    });
  });

  it("WindowsPowerShell rewrites to /install.ps1", () => {
    expect(planRoute(r("/", { ua: UA_PS_WIN }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/install.ps1",
    });
  });

  it("Invoke-WebRequest rewrites to /install.ps1", () => {
    expect(planRoute(r("/", { ua: UA_PS_IWR }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/install.ps1",
    });
  });

  it("pwsh rewrites to /install.ps1", () => {
    expect(planRoute(r("/", { ua: UA_PWSH }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/install.ps1",
    });
  });
});

describe("planRoute — apex browser default", () => {
  it("Mozilla UA rewrites to /index.html", () => {
    expect(planRoute(r("/", { ua: UA_BROWSER }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/index.html",
    });
  });

  it("missing UA falls through to /index.html", () => {
    expect(planRoute(r("/"))).toMatchObject({
      kind: "rewrite",
      assetPath: "/index.html",
    });
  });

  it("empty UA falls through to /index.html", () => {
    expect(planRoute(r("/", { ua: "" }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/index.html",
    });
  });

  it("apex HTML cache-control is short (5 min)", () => {
    const plan = planRoute(r("/", { ua: UA_BROWSER }));
    if (plan.kind !== "rewrite") throw new Error("expected rewrite");
    expect(plan.headers["cache-control"]).toMatch(/max-age=300\b/);
  });

  it("apex HTML response carries security headers", () => {
    const plan = planRoute(r("/", { ua: UA_BROWSER }));
    if (plan.kind !== "rewrite") throw new Error("expected rewrite");
    expect(plan.headers["x-content-type-options"]).toBe("nosniff");
    expect(plan.headers["referrer-policy"]).toBe(HEADERS_SECURITY["referrer-policy"]);
  });
});

describe("planRoute — method handling", () => {
  it("HEAD / honors curl UA dispatch (same plan as GET /)", () => {
    expect(planRoute(r("/", { method: "HEAD", ua: UA_CURL }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/install.sh",
    });
  });

  it("POST / does not UA-dispatch; falls through to passthrough", () => {
    expect(planRoute(r("/", { method: "POST", ua: UA_CURL }))).toMatchObject({
      kind: "passthrough",
    });
  });

  it("PUT / falls through to passthrough", () => {
    expect(planRoute(r("/", { method: "PUT", ua: UA_CURL }))).toMatchObject({
      kind: "passthrough",
    });
  });
});

describe("planRoute — explicit overrides", () => {
  it("?install=sh forces shellscript even with browser UA", () => {
    expect(planRoute(r("/?install=sh", { ua: UA_BROWSER }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/install.sh",
    });
  });

  it("?install=ps1 forces PowerShell even with curl UA", () => {
    expect(planRoute(r("/?install=ps1", { ua: UA_CURL }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/install.ps1",
    });
  });

  it("?install=html forces HTML even with curl UA", () => {
    expect(planRoute(r("/?install=html", { ua: UA_CURL }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/index.html",
    });
  });

  it("Accept: text/html escape hatch overrides curl UA when no ?install= given", () => {
    expect(
      planRoute(r("/", { ua: UA_CURL, accept: "text/html,application/xhtml+xml" })),
    ).toMatchObject({ kind: "rewrite", assetPath: "/index.html" });
  });

  it("?install=sh wins even when Accept: text/html is also present", () => {
    expect(
      planRoute(r("/?install=sh", { accept: "text/html" })),
    ).toMatchObject({ kind: "rewrite", assetPath: "/install.sh" });
  });

  it("unknown ?install= value defaults to UA-based dispatch (curl → sh)", () => {
    expect(planRoute(r("/?install=banana", { ua: UA_CURL }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/install.sh",
    });
  });

  it("unknown ?install= value with browser UA falls through to HTML", () => {
    expect(planRoute(r("/?install=xyzzy", { ua: UA_BROWSER }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/index.html",
    });
  });
});

describe("planRoute — /uninstall UA dispatch (mirror of apex)", () => {
  it("curl → /uninstall.sh with shellscript content-type", () => {
    const plan = planRoute(r("/uninstall", { ua: UA_CURL }));
    expect(plan).toEqual({
      kind: "rewrite",
      assetPath: "/uninstall.sh",
      headers: expect.objectContaining({
        "content-type": "text/x-shellscript; charset=utf-8",
        "cache-control": CACHE.INSTALL,
      }),
    });
  });

  it("PowerShell → /uninstall.ps1", () => {
    expect(planRoute(r("/uninstall", { ua: UA_PS_CORE }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/uninstall.ps1",
    });
  });

  it("trailing slash works", () => {
    expect(planRoute(r("/uninstall/", { ua: UA_WGET }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/uninstall.sh",
    });
  });

  it("browser UA gets the docs page, not the marketing page", () => {
    expect(planRoute(r("/uninstall", { ua: UA_BROWSER }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/docs.html",
    });
  });

  it("?install=ps1 override works on /uninstall too", () => {
    expect(planRoute(r("/uninstall?install=ps1", { ua: UA_CURL }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/uninstall.ps1",
    });
  });

  it("POST /uninstall does not UA-dispatch; falls through to passthrough", () => {
    expect(planRoute(r("/uninstall", { method: "POST", ua: UA_CURL }))).toMatchObject({
      kind: "passthrough",
    });
  });
});

describe("planRoute — non-apex paths", () => {
  it("/docs maps to /docs.html via rewrite", () => {
    expect(planRoute(r("/docs"))).toMatchObject({
      kind: "rewrite",
      assetPath: "/docs.html",
    });
  });

  it("/docs/ trailing slash maps to /docs.html", () => {
    expect(planRoute(r("/docs/"))).toMatchObject({
      kind: "rewrite",
      assetPath: "/docs.html",
    });
  });

  it("/install.sh direct path is passthrough (no rewrite)", () => {
    expect(planRoute(r("/install.sh"))).toMatchObject({ kind: "passthrough" });
  });

  it("/install.ps1 direct path is passthrough", () => {
    expect(planRoute(r("/install.ps1"))).toMatchObject({ kind: "passthrough" });
  });

  it("/art/foo.png is passthrough", () => {
    expect(planRoute(r("/art/foo.png"))).toMatchObject({ kind: "passthrough" });
  });

  it("/design-system.css is passthrough", () => {
    expect(planRoute(r("/design-system.css"))).toMatchObject({ kind: "passthrough" });
  });
});

describe("passthroughHeaders — content-type + cache-control by extension", () => {
  it("png gets immutable 1-year cache", () => {
    expect(passthroughHeaders("/art/x.png")["cache-control"]).toBe(CACHE.IMMUTABLE);
  });

  it("jpg gets immutable 1-year cache", () => {
    expect(passthroughHeaders("/art/x.jpg")["cache-control"]).toBe(CACHE.IMMUTABLE);
  });

  it("svg gets immutable 1-year cache", () => {
    expect(passthroughHeaders("/art/x.svg")["cache-control"]).toBe(CACHE.IMMUTABLE);
  });

  it("mp4 gets immutable 1-year cache", () => {
    expect(passthroughHeaders("/art/x.mp4")["cache-control"]).toBe(CACHE.IMMUTABLE);
  });

  it("woff2 gets immutable 1-year cache", () => {
    expect(passthroughHeaders("/fonts/x.woff2")["cache-control"]).toBe(CACHE.IMMUTABLE);
  });

  it("css gets 1-day cache", () => {
    expect(passthroughHeaders("/design-system.css")["cache-control"]).toBe(CACHE.CSS_JS);
  });

  it("js gets 1-day cache", () => {
    expect(passthroughHeaders("/tweaks.js")["cache-control"]).toBe(CACHE.CSS_JS);
  });

  it("install.sh gets short cache + shellscript content-type", () => {
    const h = passthroughHeaders("/install.sh");
    expect(h["cache-control"]).toBe(CACHE.INSTALL);
    expect(h["content-type"]).toBe("text/x-shellscript; charset=utf-8");
  });

  it("install.ps1 gets short cache + text/plain content-type", () => {
    const h = passthroughHeaders("/install.ps1");
    expect(h["cache-control"]).toBe(CACHE.INSTALL);
    expect(h["content-type"]).toBe("text/plain; charset=utf-8");
  });

  it("uninstall.sh gets short cache + shellscript content-type", () => {
    const h = passthroughHeaders("/uninstall.sh");
    expect(h["cache-control"]).toBe(CACHE.INSTALL);
    expect(h["content-type"]).toBe("text/x-shellscript; charset=utf-8");
  });

  it("uninstall.ps1 gets short cache + text/plain content-type", () => {
    const h = passthroughHeaders("/uninstall.ps1");
    expect(h["cache-control"]).toBe(CACHE.INSTALL);
    expect(h["content-type"]).toBe("text/plain; charset=utf-8");
  });

  it(".html gets HTML cache", () => {
    expect(passthroughHeaders("/foo.html")["cache-control"]).toBe(CACHE.HTML);
  });

  it("unrecognized extension gets no cache-control (assets binding default)", () => {
    expect(passthroughHeaders("/foo.unknown")["cache-control"]).toBeUndefined();
  });

  it("every passthrough response has security headers", () => {
    for (const path of [
      "/art/x.png",
      "/design-system.css",
      "/tweaks.js",
      "/install.sh",
      "/install.ps1",
      "/foo.html",
      "/foo.unknown",
    ]) {
      const h = passthroughHeaders(path);
      expect(h["x-content-type-options"]).toBe("nosniff");
      expect(h["referrer-policy"]).toBe("strict-origin-when-cross-origin");
    }
  });
});

describe("planRoute — case-insensitive UA matching", () => {
  it("CURL (uppercase) is recognized as a script sender", () => {
    expect(planRoute(r("/", { ua: "CURL/8" }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/install.sh",
    });
  });

  it("powershell (lowercase) is recognized", () => {
    expect(planRoute(r("/", { ua: "lowercase-powershell/1.0" }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/install.ps1",
    });
  });
});

describe("planRoute — UA prefix anchoring", () => {
  it("UA containing 'curl' substring (e.g. 'mycurl/1.0') does NOT match", () => {
    expect(planRoute(r("/", { ua: "mycurl/1.0" }))).toMatchObject({
      kind: "rewrite",
      assetPath: "/index.html",
    });
  });

  it("Browser UA mentioning 'curl' in product token (very rare) does not match", () => {
    expect(
      planRoute(r("/", { ua: "Mozilla/5.0 curl/8" })),
    ).toMatchObject({
      kind: "rewrite",
      assetPath: "/index.html",
    });
  });
});

// =====================================================================
// End-to-end: smoke-test the wired-up Worker against the real assets
// binding. vitest-pool-workers 0.5.x serves assets directly (Worker
// runs only on misses), so this suite verifies what assets-first mode
// permits — a small but useful contract surface.
// =====================================================================
describe("e2e via SELF.fetch (assets-first mode in test pool)", () => {
  it("/install.sh returns the script body with #!/bin/sh", async () => {
    const res = await SELF.fetch(APEX + "/install.sh");
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("#!/bin/sh");
    expect(body).toContain("BURN_VERSION");
    expect(body).toContain("BURN_INSTALL");
  });

  it("/install.ps1 returns the script body with $ErrorActionPreference", async () => {
    const res = await SELF.fetch(APEX + "/install.ps1");
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("$ErrorActionPreference");
    expect(body).toContain("BURN_VERSION");
    expect(body).toContain("BURN_INSTALL");
  });

  it("/uninstall.sh returns the script body and references the rc marker", async () => {
    const res = await SELF.fetch(APEX + "/uninstall.sh");
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("#!/bin/sh");
    expect(body).toContain("# burn (https://afterburner.sh)");
    expect(body).toContain("BURN_INSTALL");
  });

  it("/uninstall.ps1 returns the script body", async () => {
    const res = await SELF.fetch(APEX + "/uninstall.ps1");
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("$ErrorActionPreference");
    expect(body).toContain("BURN_INSTALL");
  });

  it("/index.html returns a real HTML document", async () => {
    const res = await SELF.fetch(APEX + "/index.html");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type") ?? "").toContain("text/html");
    expect((await res.text()).toLowerCase()).toContain("<!doctype html>");
  });

  it("nonexistent path returns 4xx", async () => {
    const res = await SELF.fetch(APEX + "/this-path-does-not-exist-xyzzy");
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });
});

describe("agent discovery Link headers (RFC 8288)", () => {
  // Only IANA-registered relation types may appear. `sitemap` is NOT
  // registered - the sitemap is advertised via robots.txt instead - so a
  // regression that reintroduces it must fail here.
  it("uses only IANA-registered relation types", () => {
    const rels = [...LINK_AGENT.matchAll(/rel="([^"]+)"/g)].map((m) => m[1]);
    expect(rels).toEqual(["describedby", "help"]);
    expect(LINK_AGENT).not.toContain('rel="sitemap"');
  });

  it("is a well-formed RFC 8288 field value", () => {
    for (const part of LINK_AGENT.split(", ")) {
      expect(part).toMatch(/^<\/[^>]*>; rel="[a-z-]+"(; type="[^"]+")?$/);
    }
  });

  it("points describedby at /llms.txt and help at /docs", () => {
    expect(LINK_AGENT).toContain('</llms.txt>; rel="describedby"');
    expect(LINK_AGENT).toContain('</docs>; rel="help"');
  });

  it("stamps the apex HTML response", () => {
    const plan = planRoute(r("/", { ua: UA_BROWSER, accept: "text/html" }));
    expect(plan.headers["link"]).toBe(LINK_AGENT);
  });

  it("stamps /docs", () => {
    expect(planRoute(r("/docs")).headers["link"]).toBe(LINK_AGENT);
  });

  it("stamps a directly requested .html asset", () => {
    expect(passthroughHeaders("/index.html")["link"]).toBe(LINK_AGENT);
  });

  it("does NOT stamp the install script (nothing to describe)", () => {
    const plan = planRoute(r("/", { ua: UA_CURL }));
    expect(plan.headers["link"]).toBeUndefined();
  });

  it("does NOT stamp css/js or image assets", () => {
    expect(passthroughHeaders("/design-system.css")["link"]).toBeUndefined();
    expect(passthroughHeaders("/tweaks.js")["link"]).toBeUndefined();
    expect(passthroughHeaders("/art/og-image.png")["link"]).toBeUndefined();
  });

  // The three HTML-producing branches must agree; they share htmlHeaders()
  // precisely so they cannot drift.
  it("every HTML branch emits an identical header set", () => {
    const apex = planRoute(r("/", { ua: UA_BROWSER, accept: "text/html" })).headers;
    const docs = planRoute(r("/docs")).headers;
    const forced = planRoute(r("/?install=html", { ua: UA_CURL })).headers;
    expect(apex).toEqual(htmlHeaders());
    expect(docs).toEqual(htmlHeaders());
    expect(forced).toEqual(htmlHeaders());
  });

  it("html headers still carry the security headers", () => {
    expect(htmlHeaders()).toMatchObject(HEADERS_SECURITY);
    expect(htmlHeaders()["cache-control"]).toBe(CACHE.HTML);
  });
});
