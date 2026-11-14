#!/usr/bin/env node
/**
 * IT Glue MCP Server
 *
 * This MCP server provides tools for interacting with IT Glue API.
 * It accepts credentials via HTTP headers from the MCP Gateway.
 *
 * The MCP server factory and IT Glue client live in `mcp-server.ts` (which is
 * side-effect free and shared with the Cloudflare Workers entrypoint in
 * `worker.ts`). This file owns the Node-only transports (stdio + Node HTTP).
 */

import { createServer, IncomingMessage, ServerResponse, type Server } from "node:http";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  createMcpServer,
  type GatewayCredentials,
  type ITGlueRegion,
} from "./mcp-server.js";
import { runWithServerRef, bindServerRef } from "./utils/server-ref.js";
import { verifyS2sHeader } from "./s2s-verify.js";
import {
  NonceCache,
  ReportRateLimiter,
  assertRequireSignedHeaders,
  effectiveMinVersion,
  handleGatewayRequest,
  type GatewayLogger,
} from "./itsl/s2s-v3.js";

/** Audience cred-router signs for this vendor (finishSignedProxyRequest vendor 'itglue'). */
const S2S_AUDIENCE = "itglue";
/** The legacy version enforced today: v1 (`t=..,v1=..`). No env var tightens it. */
const S2S_FLOOR = 1;
const MIN_S2S_SECRET_LENGTH = 32;

/**
 * Every header this backend reads for credentials or base URL. cred-router
 * sets x-itglue-api-key and x-itglue-region; the rest it never sets (it strips
 * client headers), so one that arrives is a caller's. Present means it must be
 * covered by the v3 signature, in report and enforce mode alike.
 */
const REQUIRE_SIGNED_HEADERS = [
  "x-itglue-api-key",
  "x-api-key",
  "x-itglue-jwt",
  "x-itglue-base-url",
  "x-itglue-region",
];

/** One per process: v3 nonces are single-use inside the skew window. */
const nonceCache = new NonceCache();
const reportLimiter = new ReportRateLimiter();
const failureLimiter = new ReportRateLimiter();

const logLine = (level: string, msg: string, meta?: Record<string, unknown>): void => {
  console.error(JSON.stringify({ level, msg, ...meta }));
};
const logger: GatewayLogger & { info(msg: string, meta?: Record<string, unknown>): void } = {
  info: (msg, meta) => logLine("info", msg, meta),
  warn: (msg, meta) => logLine("warn", msg, meta),
  error: (msg, meta) => logLine("error", msg, meta),
};

// Re-export the shared factory + IT Glue client/helpers so existing consumers
// (and tests) that import from the package entry keep working after the
// side-effect-free factory was extracted into `mcp-server.ts`.
export {
  createMcpServer,
  createClient,
  cleanCredential,
  getCredentialsFromEnv,
  sanitizeCredentials,
  ITGlueClient,
  buildFolderPickerOptions,
  buildUserMetricsDateFilter,
  USER_METRIC_SORT_FIELDS,
  createDocumentWithContent,
  documentBodyOmittedNote,
  folderedDocumentsIncludedNote,
  listDocumentFoldersViaApiKey,
  nameFallbackNote,
  parseFolderReference,
  requestDocumentsWithFolderDefault,
  rootLevelDocumentsNote,
  searchByNameWithFallback,
  stripDocumentBodies,
  stripPasswordValues,
} from "./mcp-server.js";
export type {
  DocumentSearchAttempt,
  GatewayCredentials,
  ITGlueRegion,
  NameFallbackResult,
} from "./mcp-server.js";

/**
 * Start with stdio transport (default for local/CLI usage)
 */
async function startStdioTransport(): Promise<void> {
  const server = createMcpServer();
  // stdio is single-session (one process = one caller), so there is no
  // concurrent tenant to isolate from — bind once for the process
  // lifetime rather than per-request. See utils/server-ref.ts.
  bindServerRef(server);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("IT Glue MCP server running on stdio");
}

/**
 * Start with HTTP Streamable transport (for Docker/cloud deployment)
 * Supports both env-based and gateway (header-based) credential modes.
 *
 * Every /mcp request goes through the shared S2S wrapper (handleGatewayRequest):
 * legacy v1 (`t=..,v1=..`) and request-bound v3 are both accepted until
 * ITSL_S2S_MIN_VERSION=3. Returns the listening server (tests close it).
 */
export async function startHttpTransport(): Promise<Server> {
  const port = parseInt(process.env.MCP_HTTP_PORT || "8080", 10);
  const host = process.env.MCP_HTTP_HOST || "0.0.0.0";
  const isGatewayMode = process.env.AUTH_MODE === "gateway";

  // Fail closed: HTTP mode never serves without a real S2S secret. Neither the
  // secret nor its length is ever logged.
  const s2sSecret = process.env.CONDUIT_S2S_SECRET || "";
  if (s2sSecret.length < MIN_S2S_SECRET_LENGTH) {
    throw new Error(
      "Refusing to start HTTP server: CONDUIT_S2S_SECRET is missing or shorter than 32 characters. " +
        "Set it to the gateway-provisioned secret (openssl rand -hex 32)."
    );
  }
  assertRequireSignedHeaders(REQUIRE_SIGNED_HEADERS);

  // Operator switch for the S2S v3 rollout. Passed through raw: anything that is
  // not an integer 1..3 is treated as 3 by the verifier (a typo can only tighten).
  const minVersion = Number(process.env.ITSL_S2S_MIN_VERSION ?? String(S2S_FLOOR));
  const effectiveMin = effectiveMinVersion(S2S_FLOOR, minVersion);
  logger.info("S2S configuration", {
    effectiveMinVersion: effectiveMin,
    headerRule: effectiveMin === 3 ? "enforced" : "report mode",
  });

  const httpServer = createServer((req: IncomingMessage, res: ServerResponse) => {
    // Raw target, not a parsed URL: the signed path is exactly what was sent.
    const rawTarget = req.url ?? "/";
    const queryAt = rawTarget.indexOf("?");
    const pathname = queryAt === -1 ? rawTarget : rawTarget.slice(0, queryAt);

    // Health endpoint - no auth required (container probe path)
    if (pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: "ok",
          transport: "http",
          authMode: isGatewayMode ? "gateway" : "env",
          timestamp: new Date().toISOString(),
        })
      );
      return;
    }

    // Only the exact MCP path is served; everything else is 404 before auth.
    if (rawTarget !== "/mcp") {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found", endpoints: ["/mcp", "/health"] }));
      return;
    }

    // The shared wrapper runs the S2S check FIRST (before method checks or
    // credential extraction), reads the body once, and never rejects.
    void handleGatewayRequest(
      req,
      res,
      {
        secret: s2sSecret,
        aud: S2S_AUDIENCE,
        floor: S2S_FLOOR,
        minVersion,
        verifyLegacy: (headerValue) =>
          verifyS2sHeader(headerValue, s2sSecret) ? 1 : 0,
        nonceCache,
        reportLimiter,
        failureLimiter,
        logger,
        requireSignedHeaders: REQUIRE_SIGNED_HEADERS,
      },
      ({ parsedBody }) => {
        // Only POST is supported in stateless mode
        if (req.method !== "POST") {
          res.writeHead(405, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            jsonrpc: "2.0",
            error: { code: -32000, message: "Method not allowed" },
            id: null,
          }));
          return;
        }

        // In gateway mode, extract credentials from headers; otherwise undefined (env fallback)
        let gatewayCredentials: GatewayCredentials | undefined;
        if (isGatewayMode) {
          const headers = req.headers as Record<string, string | string[] | undefined>;
          const apiKey =
            (headers["x-itglue-api-key"] as string) ||
            (headers["x-api-key"] as string);
          const jwt = (headers["x-itglue-jwt"] as string) || undefined;

          if (!apiKey && !jwt) {
            res.writeHead(401, { "Content-Type": "application/json" });
            res.end(
              JSON.stringify({
                error: "Missing credentials",
                message: "Gateway mode requires X-ITGlue-API-Key or X-ITGlue-JWT header",
                required: ["X-ITGlue-API-Key OR X-ITGlue-JWT"],
              })
            );
            return;
          }

          const baseUrl = headers["x-itglue-base-url"] as string | undefined;
          const region = headers["x-itglue-region"] as string | undefined;

          gatewayCredentials = {
            apiKey,
            jwt,
            region: (region || "us") as ITGlueRegion,
            baseUrl: baseUrl || undefined,
          };
        }

        // Stateless: create fresh server + transport for each request
        const server = createMcpServer(gatewayCredentials);
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: undefined,
          enableJsonResponse: true,
        });

        res.on("close", () => {
          transport.close();
          server.close();
        });

        // Bind this request's server into the per-request async context
        // (not a module-level global) so elicitation helpers resolve *this*
        // server/transport even after await gaps, and never a concurrent
        // request's — see utils/server-ref.ts. The whole connect/then/catch
        // chain must stay inside this callback so the bound context survives
        // every await gap between here and any later getServerRef() call.
        return runWithServerRef(server, () =>
          server.connect(transport as unknown as Transport).then(() => {
            // The wrapper already read the body; hand the parsed JSON on.
            return transport.handleRequest(req, res, parsedBody);
          }).catch((err) => {
            console.error("MCP transport error:", err);
            if (!res.headersSent) {
              res.writeHead(500, { "Content-Type": "application/json" });
              res.end(JSON.stringify({
                jsonrpc: "2.0",
                error: { code: -32603, message: "Internal error" },
                id: null,
              }));
            }
          })
        );
      },
    );
  });

  await new Promise<void>((resolve) => {
    httpServer.listen(port, host, () => {
      const addr = httpServer.address();
      const bound = typeof addr === "object" && addr ? addr.port : port;
      console.error(`IT Glue MCP server listening on http://${host}:${bound}/mcp`);
      console.error(`Health check available at http://${host}:${bound}/health`);
      console.error(
        `Authentication mode: ${isGatewayMode ? "gateway (header-based)" : "env (environment variables)"}`
      );
      resolve();
    });
  });

  // Graceful shutdown
  const shutdown = async () => {
    console.error("Shutting down IT Glue MCP server...");
    await new Promise<void>((resolve, reject) => {
      httpServer.close((err) => (err ? reject(err) : resolve()));
    });
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
  return httpServer;
}

// Start the server
async function main() {
  const transportType = process.env.MCP_TRANSPORT || "stdio";

  if (transportType === "http") {
    await startHttpTransport();
  } else {
    await startStdioTransport();
  }
}

// Only bootstrap the server when run as a process, not when imported for tests.
if (process.env.NODE_ENV !== "test") {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
