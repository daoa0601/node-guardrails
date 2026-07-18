import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import { connect } from "node:net";

import { afterEach, describe, expect, it } from "vitest";

import {
  HttpGuardrailError,
  matchesBearerToken,
  readBoundedBody,
  readBoundedJson,
  sendJson,
} from "../src/http.js";

const close: Array<() => Promise<void>> = [];

afterEach(async () => {
  await Promise.all(close.splice(0).map((stop) => stop()));
});

async function serve(
  handler: (
    request: IncomingMessage,
    response: ServerResponse,
  ) => Promise<void> | void,
): Promise<string> {
  const server = createServer((request, response) => {
    void Promise.resolve(handler(request, response)).catch((error: unknown) => {
      const known = error instanceof HttpGuardrailError ? error : undefined;
      sendJson(response, known?.status ?? 500, {
        kind: known?.kind ?? "unknown",
      });
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  close.push(
    () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) =>
          error === undefined ? resolve() : reject(error),
        );
      }),
  );
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

async function rawExchange(
  origin: string,
  payload: string,
  options: { readonly keepRequestOpen?: boolean } = {},
): Promise<string> {
  const url = new URL(origin);
  return new Promise<string>((resolve, reject) => {
    const socket = connect({ host: url.hostname, port: Number(url.port) });
    let response = "";
    let settled = false;
    const timer = setTimeout(() => {
      socket.destroy();
      if (!settled) reject(new Error("Raw HTTP exchange did not close"));
    }, 1_000);
    const finish = (): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(response);
    };
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      response += chunk;
    });
    socket.once("error", reject);
    socket.once("close", finish);
    socket.once("connect", () => {
      if (options.keepRequestOpen === true) socket.write(payload);
      else socket.end(payload);
    });
  });
}

const responsePolicy = (response: ServerResponse) => ({
  action: "respond-and-close" as const,
  response,
  timeoutMs: 100,
});

describe("HTTP guardrails", () => {
  it("reads bounded JSON and writes a hardened JSON response", async () => {
    const origin = await serve(async (request, response) => {
      sendJson(
        response,
        201,
        await readBoundedJson(request, {
          limitBytes: 128,
          rejection: responsePolicy(response),
        }),
        {
          headers: { "x-request-id": "request-1" },
          newline: true,
        },
      );
    });
    const response = await fetch(origin, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ok: true }),
    });

    expect(response.status).toBe(201);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("x-request-id")).toBe("request-1");
    expect(await response.text()).toBe('{"ok":true}\n');
  });

  it.each([
    [{ "content-type": "text/plain" }, "{}", "media_type_unsupported"],
    [{ "content-type": "application/json" }, "not-json", "json_invalid"],
    [
      { "content-type": "application/json", "content-encoding": "gzip" },
      "{}",
      "content_encoding_unsupported",
    ],
  ])("rejects malformed request framing", async (headers, body, kind) => {
    const origin = await serve(async (request, response) => {
      sendJson(
        response,
        200,
        await readBoundedJson(request, {
          limitBytes: 128,
          rejection: responsePolicy(response),
        }),
      );
    });
    const response = await fetch(origin, { method: "POST", headers, body });
    expect(await response.json()).toEqual({ kind });
  });

  it("enforces streamed byte limits", async () => {
    const origin = await serve(async (request, response) => {
      sendJson(response, 200, {
        size: (
          await readBoundedBody(request, {
            limitBytes: 3,
            rejection: responsePolicy(response),
          })
        ).length,
      });
    });
    const response = await fetch(origin, { method: "POST", body: "four" });
    expect(response.status).toBe(413);
    expect(await response.json()).toEqual({ kind: "body_too_large" });
  });

  it("accepts plain chunked framing and rejects stacked transfer codings", async () => {
    const origin = await serve(async (request, response) => {
      sendJson(
        response,
        200,
        await readBoundedJson(request, {
          limitBytes: 128,
          rejection: responsePolicy(response),
        }),
      );
    });
    const body = '{"ok":true}';
    const request = (transferEncoding: string) =>
      [
        "POST / HTTP/1.1",
        `Host: ${new URL(origin).host}`,
        "Content-Type: application/json",
        `Transfer-Encoding: ${transferEncoding}`,
        "Connection: close",
        "",
        body.length.toString(16),
        body,
        "0",
        "",
        "",
      ].join("\r\n");

    const unsupported = await rawExchange(origin, request("gzip, chunked"));
    expect(unsupported).toMatch(/^HTTP\/1\.1 400/u);
    expect(unsupported).toContain("transfer_encoding_unsupported");
    const chunked = await rawExchange(origin, request("chunked"));
    expect(chunked).toMatch(/^HTTP\/1\.1 200/u);
    expect(chunked).toContain('{"ok":true}');
  });

  it("responds then closes an incomplete rejected request within its cleanup deadline", async () => {
    const origin = await serve(async (request, response) => {
      sendJson(
        response,
        200,
        await readBoundedJson(request, {
          limitBytes: 128,
          rejection: responsePolicy(response),
        }),
      );
    });
    const startedAt = Date.now();
    const rejected = await rawExchange(
      origin,
      [
        "POST / HTTP/1.1",
        `Host: ${new URL(origin).host}`,
        "Content-Type: text/plain",
        "Content-Length: 100",
        "Connection: keep-alive",
        "",
        "partial",
      ].join("\r\n"),
      { keepRequestOpen: true },
    );

    expect(rejected).toMatch(/^HTTP\/1\.1 415/u);
    expect(rejected).toContain("media_type_unsupported");
    expect(rejected.toLowerCase()).toContain("connection: close");
    expect(Date.now() - startedAt).toBeLessThan(500);
  });

  it("supports immediate destruction when no error response is required", async () => {
    const origin = await serve(async (request) => {
      await readBoundedJson(request, {
        limitBytes: 128,
        rejection: { action: "destroy" },
      });
    });
    const startedAt = Date.now();
    const rejected = await rawExchange(
      origin,
      [
        "POST / HTTP/1.1",
        `Host: ${new URL(origin).host}`,
        "Content-Type: text/plain",
        "Content-Length: 100",
        "",
        "partial",
      ].join("\r\n"),
      { keepRequestOpen: true },
    );

    expect(rejected).toBe("");
    expect(Date.now() - startedAt).toBeLessThan(500);
  });

  it("compares bearer credentials exactly", () => {
    expect(matchesBearerToken("Bearer secret", "secret")).toBe(true);
    expect(matchesBearerToken("bearer secret", "secret")).toBe(false);
    expect(matchesBearerToken(["Bearer secret"], "secret")).toBe(false);
    expect(matchesBearerToken(undefined, "secret")).toBe(false);
  });
});
