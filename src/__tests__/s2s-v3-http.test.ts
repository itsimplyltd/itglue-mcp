/**
 * S2S legacy v1 + v3 at the HTTP boundary of the real server (startHttpTransport):
 * floor 1, credential headers bound by the v3 signature, boot checks, routing,
 * and the redirect guard on outbound vendor calls.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { connect } from "node:net";
import { createServer as createHttpServer, type Server } from "node:http";
import { signV1, signV3 } from "./s2s-v3-signer.js";
import { startHttpTransport, ITGlueClient } from "../index.js";

const SECRET = "test-s2s-v3-http-secret-do-not-use-in-prod";
const HOST = "127.0.0.1";
const KEY = "test-api-key-not-real";
const ENV_KEYS = ["CONDUIT_S2S_SECRET", "ITSL_S2S_MIN_VERSION", "AUTH_MODE", "MCP_HTTP_PORT", "MCP_HTTP_HOST"];

const listTools = { jsonrpc: "2.0", method: "tools/list", id: 1 };

async function start(minVersion?: string): Promise<{ server: Server; port: number; logs: string[] }> {
  Object.assign(process.env, { CONDUIT_S2S_SECRET: SECRET, AUTH_MODE: "gateway", MCP_HTTP_PORT: "0", MCP_HTTP_HOST: HOST });
  if (minVersion === undefined) delete process.env.ITSL_S2S_MIN_VERSION;
  else process.env.ITSL_S2S_MIN_VERSION = minVersion;
  const logs: string[] = [];
  const spy = vi.spyOn(console, "error").mockImplementation((...a: unknown[]) => {
    logs.push(a.map(String).join(" "));
  });
  try {
    const server = await startHttpTransport();
    return { server, port: (server.address() as { port: number }).port, logs };
  } finally {
    spy.mockRestore();
  }
}

const close = (s: Server) => new Promise<void>((r) => s.close(() => r()));

const post = (port: number, headers: Record<string, string>, body: unknown = listTools, path = "/mcp") =>
  fetch(`http://${HOST}:${port}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify(body),
  });

/** Headers as cred-router sends them: credential and region, both signed. */
const cred = (): Record<string, string> => ({ "x-itglue-api-key": KEY, "x-itglue-region": "us" });
const v3 = (signed: Record<string, string>, extra: Record<string, string> = {}, body: unknown = listTools, n?: string) => ({
  "x-gateway-s2s": signV3(SECRET, { aud: "itglue", method: "POST", path: "/mcp", body: JSON.stringify(body), headers: signed, ...(n ? { n } : {}) }),
  ...signed,
  ...extra,
});
const v1 = (extra: Record<string, string> = cred()) => ({ "x-gateway-s2s": signV1(SECRET), ...extra });

describe("S2S legacy v1 + v3 at the HTTP boundary (floor 1, min 1)", () => {
  let s: { server: Server; port: number; logs: string[] };
  beforeAll(async () => {
    s = await start();
  });
  afterAll(async () => {
    await close(s.server);
    for (const k of ENV_KEYS) delete process.env[k];
  });

  it("logs the effective minimum version and the header rule mode at boot", () => {
    const line = s.logs.find((l) => l.includes("S2S configuration"));
    expect(line).toBeDefined();
    expect(JSON.parse(line as string)).toMatchObject({ level: "info", effectiveMinVersion: 1, headerRule: "report mode" });
    expect(s.logs.join("\n")).not.toContain(SECRET);
  });

  it("legacy v1 is accepted at the floor", async () => {
    expect((await post(s.port, v1())).status).toBe(200);
  });

  it("no S2S header, garbage, or a wrong-secret v1 is refused", async () => {
    expect((await post(s.port, cred())).status).toBe(401);
    expect((await post(s.port, { ...cred(), "x-gateway-s2s": "garbage" })).status).toBe(401);
    expect((await post(s.port, { ...cred(), "x-gateway-s2s": signV1("another-secret-that-is-long-enough-123456") })).status).toBe(401);
  });

  it("v3 is accepted", async () => {
    expect((await post(s.port, v3(cred()))).status).toBe(200);
  });

  it("a signed credential set (every credential header the backend reads) is honoured", async () => {
    const all = { ...cred(), "x-api-key": "k2", "x-itglue-jwt": "j", "x-itglue-base-url": "https://api.itglue.com" };
    expect((await post(s.port, v3(all))).status).toBe(200);
  });

  it.each(["x-itglue-api-key", "x-api-key", "x-itglue-jwt", "x-itglue-base-url", "x-itglue-region"])(
    "v3 with %s present but unsigned is refused, even in report mode",
    async (name) => {
      const signed = { ...cred() } as Record<string, string>;
      delete signed[name];
      if (name === "x-itglue-api-key") signed["x-itglue-region"] = "us";
      const res = await post(s.port, v3(signed, { [name]: "injected" }));
      expect(res.status).toBe(401);
    },
  );

  it("a replayed v3 request and a tampered body are refused", async () => {
    const h = v3(cred(), {}, listTools, "ab".repeat(16));
    expect((await post(s.port, h)).status).toBe(200);
    expect((await post(s.port, h)).status).toBe(401);
    expect((await post(s.port, v3(cred()), { ...listTools, id: 99 })).status).toBe(401);
  });

  it("v3 for another audience or with the wrong secret is refused", async () => {
    const sig = (secret: string, aud: string) =>
      signV3(secret, { aud, method: "POST", path: "/mcp", body: JSON.stringify(listTools), headers: cred() });
    expect((await post(s.port, { "x-gateway-s2s": sig(SECRET, "other"), ...cred() })).status).toBe(401);
    expect((await post(s.port, { "x-gateway-s2s": sig("wrong-secret-must-not-verify-at-all-12", "itglue"), ...cred() })).status).toBe(401);
  });

  it("existing handling is unchanged: valid S2S but no credential is a 401, GET is a 405", async () => {
    expect((await post(s.port, v3({}))).status).toBe(401);
    const res = await fetch(`http://${HOST}:${s.port}/mcp`, {
      method: "GET",
      headers: { "x-gateway-s2s": signV3(SECRET, { aud: "itglue", method: "GET", path: "/mcp", headers: cred() }), ...cred() },
    });
    expect(res.status).toBe(405);
  });

  it("an unknown path is a 404 before authentication; /mcp with a query or slash is not /mcp", async () => {
    expect((await post(s.port, {}, listTools, "/nope")).status).toBe(404);
    expect((await post(s.port, v1(), listTools, "/mcp?x=1")).status).toBe(404);
    expect((await post(s.port, v1(), listTools, "/mcp/")).status).toBe(404);
    expect((await fetch(`http://${HOST}:${s.port}/health`)).status).toBe(200);
  });

  it("a socket aborted mid-body does not take the server down", async () => {
    const sig = signV3(SECRET, { aud: "itglue", method: "POST", path: "/mcp", body: JSON.stringify(listTools), headers: cred() });
    const sock = connect(s.port, HOST);
    sock.on("error", () => {});
    await new Promise<void>((r) => sock.once("connect", () => r()));
    const hdrs = Object.entries(cred()).map(([k, v]) => `${k}: ${v}\r\n`).join("");
    sock.write(`POST /mcp HTTP/1.1\r\nHost: x\r\nX-Gateway-S2S: ${sig}\r\n${hdrs}Content-Length: 1000\r\n\r\n0123456789`);
    await new Promise((r) => setTimeout(r, 100));
    sock.destroy();
    await new Promise((r) => setTimeout(r, 100));
    expect((await fetch(`http://${HOST}:${s.port}/health`)).status).toBe(200);
    expect((await post(s.port, v3(cred()))).status).toBe(200);
  });
});

describe("minimum version switch", () => {
  it("legacy is refused at min 2 and at min 3, v3 still passes; the log says enforced at 3", async () => {
    for (const min of ["2", "3"]) {
      const s = await start(min);
      try {
        expect((await post(s.port, v1())).status).toBe(401);
        expect((await post(s.port, v3(cred()))).status).toBe(200);
        const line = JSON.parse(s.logs.find((l) => l.includes("S2S configuration")) as string);
        expect(line.effectiveMinVersion).toBe(Number(min));
        expect(line.headerRule).toBe(min === "3" ? "enforced" : "report mode");
      } finally {
        await close(s.server);
      }
    }
    for (const k of ENV_KEYS) delete process.env[k];
  });

  it("a garbage minimum is treated as 3: legacy refused", async () => {
    const s = await start("garbage");
    try {
      expect((await post(s.port, v1())).status).toBe(401);
    } finally {
      await close(s.server);
      for (const k of ENV_KEYS) delete process.env[k];
    }
  });
});

describe("boot check", () => {
  it("refuses to start without an S2S secret of at least 32 characters", async () => {
    Object.assign(process.env, { AUTH_MODE: "gateway", MCP_HTTP_PORT: "0", MCP_HTTP_HOST: HOST });
    try {
      for (const bad of [undefined, "", "short", "x".repeat(31)]) {
        if (bad === undefined) delete process.env.CONDUIT_S2S_SECRET;
        else process.env.CONDUIT_S2S_SECRET = bad;
        await expect(startHttpTransport()).rejects.toThrow(/CONDUIT_S2S_SECRET/);
      }
    } finally {
      for (const k of ENV_KEYS) delete process.env[k];
    }
  });
});

describe("outbound vendor redirects fail closed", () => {
  it("a 3xx from the vendor is an error and the redirect target is never contacted", async () => {
    let targetHits = 0;
    const target = createHttpServer((_q, r) => {
      targetHits++;
      r.end("{}");
    });
    await new Promise<void>((r) => target.listen(0, HOST, () => r()));
    const tport = (target.address() as { port: number }).port;
    const vendor = createHttpServer((_q, r) => {
      r.writeHead(302, { Location: `http://${HOST}:${tport}/steal` });
      r.end();
    });
    await new Promise<void>((r) => vendor.listen(0, HOST, () => r()));
    const vport = (vendor.address() as { port: number }).port;
    try {
      const client = new ITGlueClient({ apiKey: KEY, baseUrl: `http://${HOST}:${vport}` });
      await expect(client.request("/organizations")).rejects.toThrow();
      await expect(client.post("/organizations", {})).rejects.toThrow();
      await expect(client.patch("/organizations/1", {})).rejects.toThrow();
      await expect(client.delete("/organizations/1")).rejects.toThrow();
      expect(targetHits).toBe(0);
    } finally {
      await close(vendor);
      await close(target);
    }
  });
});
