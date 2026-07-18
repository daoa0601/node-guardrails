import { timingSafeEqual } from "node:crypto";
import type {
  IncomingMessage,
  OutgoingHttpHeaders,
  ServerResponse,
} from "node:http";

export type HttpGuardrailFailureKind =
  | "aborted"
  | "body_too_large"
  | "content_encoding_unsupported"
  | "content_length_invalid"
  | "json_invalid"
  | "media_type_unsupported"
  | "transfer_encoding_unsupported";

export class HttpGuardrailError extends Error {
  readonly kind: HttpGuardrailFailureKind;
  readonly status: 400 | 413 | 415;

  constructor(options: {
    readonly kind: HttpGuardrailFailureKind;
    readonly message: string;
    readonly status: 400 | 413 | 415;
    readonly cause?: unknown;
  }) {
    super(
      options.message,
      options.cause === undefined ? undefined : { cause: options.cause },
    );
    this.name = "HttpGuardrailError";
    this.kind = options.kind;
    this.status = options.status;
  }
}

export interface ReadBoundedBodyOptions {
  readonly limitBytes: number;
  readonly signal?: AbortSignal;
  readonly rejectContentEncoding?: boolean;
  readonly rejection: RejectedRequestPolicy;
}

export type RejectedRequestPolicy =
  | { readonly action: "destroy" }
  | {
      readonly action: "respond-and-close";
      readonly response: ServerResponse;
      readonly timeoutMs: number;
    };

const rejectionStarted = new WeakSet<IncomingMessage>();

function validateLimit(limitBytes: number): void {
  if (!Number.isSafeInteger(limitBytes) || limitBytes < 0) {
    throw new TypeError("limitBytes must be a non-negative safe integer");
  }
}

function validateRejectionPolicy(policy: RejectedRequestPolicy): void {
  if (
    policy.action === "respond-and-close" &&
    (!Number.isSafeInteger(policy.timeoutMs) || policy.timeoutMs <= 0)
  ) {
    throw new TypeError("rejection.timeoutMs must be a positive safe integer");
  }
}

function oneHeader(
  value: string | ReadonlyArray<string> | undefined,
): string | undefined {
  return typeof value === "string" ? value : undefined;
}

export function requestMediaType(request: IncomingMessage): string | undefined {
  return oneHeader(request.headers["content-type"])
    ?.split(";", 1)[0]
    ?.trim()
    .toLowerCase();
}

/**
 * Applies the caller-selected cleanup policy after rejecting an inbound body. `destroy` closes the
 * request immediately. `respond-and-close` allows a bounded error response: it disables keep-alive,
 * drains only until the response/declared timeout closes the connection, and destroys an incomplete
 * request at that boundary. No policy leaves an unread rejected request attached to keep-alive.
 */
export function rejectRequestBody(
  request: IncomingMessage,
  policy: RejectedRequestPolicy,
): void {
  validateRejectionPolicy(policy);
  if (
    rejectionStarted.has(request) ||
    request.destroyed ||
    request.readableEnded
  )
    return;
  rejectionStarted.add(request);

  if (policy.action === "destroy") {
    request.destroy();
    return;
  }

  const response = policy.response;
  if (response.destroyed || response.headersSent) {
    request.destroy();
    return;
  }
  response.shouldKeepAlive = false;
  response.setHeader("connection", "close");

  let timer: NodeJS.Timeout | undefined;
  const cleanup = (): void => {
    if (timer !== undefined) clearTimeout(timer);
    request.off("end", bodyFinished);
    request.off("close", bodyFinished);
    response.off("close", closeIncomplete);
  };
  const bodyFinished = (): void => cleanup();
  const closeIncomplete = (): void => {
    cleanup();
    if (!request.complete && !request.destroyed) request.destroy();
  };
  request.once("end", bodyFinished);
  request.once("close", bodyFinished);
  response.once("close", closeIncomplete);
  timer = setTimeout(closeIncomplete, policy.timeoutMs);
  timer.unref();
  request.resume();
}

function rejectWithCleanup(
  request: IncomingMessage,
  options: ReadBoundedBodyOptions,
  error: HttpGuardrailError,
): never {
  rejectRequestBody(request, options.rejection);
  throw error;
}

export async function readBoundedBody(
  request: IncomingMessage,
  options: ReadBoundedBodyOptions,
): Promise<Buffer> {
  validateLimit(options.limitBytes);
  validateRejectionPolicy(options.rejection);
  const transferEncoding = oneHeader(request.headers["transfer-encoding"]);
  if (
    request.headers["transfer-encoding"] !== undefined &&
    (transferEncoding === undefined ||
      transferEncoding.trim().toLowerCase() !== "chunked")
  ) {
    rejectWithCleanup(
      request,
      options,
      new HttpGuardrailError({
        kind: "transfer_encoding_unsupported",
        message: "Transfer-Encoding must be plain chunked framing",
        status: 400,
      }),
    );
  }
  if (
    request.headers["transfer-encoding"] !== undefined &&
    request.headers["content-length"] !== undefined
  ) {
    rejectWithCleanup(
      request,
      options,
      new HttpGuardrailError({
        kind: "content_length_invalid",
        message: "Content-Length cannot be combined with Transfer-Encoding",
        status: 400,
      }),
    );
  }
  if (
    options.rejectContentEncoding !== false &&
    request.headers["content-encoding"] !== undefined
  ) {
    rejectWithCleanup(
      request,
      options,
      new HttpGuardrailError({
        kind: "content_encoding_unsupported",
        message: "Encoded request bodies are not accepted",
        status: 415,
      }),
    );
  }
  const declaredHeader = oneHeader(request.headers["content-length"]);
  if (
    request.headers["content-length"] !== undefined &&
    (declaredHeader === undefined || !/^[0-9]+$/u.test(declaredHeader))
  ) {
    rejectWithCleanup(
      request,
      options,
      new HttpGuardrailError({
        kind: "content_length_invalid",
        message: "Content-Length is invalid",
        status: 400,
      }),
    );
  }
  if (declaredHeader !== undefined) {
    const declared = Number(declaredHeader);
    if (!Number.isSafeInteger(declared)) {
      rejectWithCleanup(
        request,
        options,
        new HttpGuardrailError({
          kind: "content_length_invalid",
          message: "Content-Length is invalid",
          status: 400,
        }),
      );
    }
    if (declared > options.limitBytes) {
      rejectWithCleanup(
        request,
        options,
        new HttpGuardrailError({
          kind: "body_too_large",
          message: `Request body exceeds the ${options.limitBytes}-byte limit`,
          status: 413,
        }),
      );
    }
  }

  const chunks: Array<Buffer> = [];
  let total = 0;
  const abort = (): void => {
    const cause = options.signal?.reason;
    request.destroy(cause instanceof Error ? cause : undefined);
  };
  if (options.signal?.aborted === true) abort();
  else options.signal?.addEventListener("abort", abort, { once: true });
  try {
    for await (const raw of request.iterator({ destroyOnReturn: false })) {
      if (options.signal?.aborted === true) {
        throw new HttpGuardrailError({
          kind: "aborted",
          message: "Request body reading was aborted",
          status: 400,
          cause: options.signal.reason,
        });
      }
      const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
      total += chunk.byteLength;
      if (total > options.limitBytes) {
        throw new HttpGuardrailError({
          kind: "body_too_large",
          message: `Request body exceeds the ${options.limitBytes}-byte limit`,
          status: 413,
        });
      }
      chunks.push(chunk);
    }
  } catch (cause) {
    if (cause instanceof HttpGuardrailError) {
      rejectRequestBody(request, options.rejection);
      throw cause;
    }
    if (options.signal?.aborted === true) {
      throw new HttpGuardrailError({
        kind: "aborted",
        message: "Request body reading was aborted",
        status: 400,
        cause: options.signal.reason ?? cause,
      });
    }
    throw cause;
  } finally {
    options.signal?.removeEventListener("abort", abort);
  }
  if (options.signal?.aborted === true) {
    throw new HttpGuardrailError({
      kind: "aborted",
      message: "Request body reading was aborted",
      status: 400,
      cause: options.signal.reason,
    });
  }
  return Buffer.concat(chunks, total);
}

export async function readBoundedJson(
  request: IncomingMessage,
  options: ReadBoundedBodyOptions,
): Promise<unknown> {
  validateRejectionPolicy(options.rejection);
  if (requestMediaType(request) !== "application/json") {
    rejectWithCleanup(
      request,
      options,
      new HttpGuardrailError({
        kind: "media_type_unsupported",
        message: "Content-Type must be application/json",
        status: 415,
      }),
    );
  }
  const body = await readBoundedBody(request, options);
  try {
    return JSON.parse(body.toString("utf8")) as unknown;
  } catch (cause) {
    throw new HttpGuardrailError({
      kind: "json_invalid",
      message: "Request body must contain valid JSON",
      status: 400,
      cause,
    });
  }
}

export function matchesBearerToken(
  authorization: string | ReadonlyArray<string> | undefined,
  token: string,
): boolean {
  if (typeof authorization !== "string") return false;
  const expected = Buffer.from(`Bearer ${token}`, "utf8");
  const observed = Buffer.from(authorization, "utf8");
  return (
    observed.byteLength === expected.byteLength &&
    timingSafeEqual(observed, expected)
  );
}

export interface SendJsonOptions {
  readonly headers?: OutgoingHttpHeaders;
  readonly newline?: boolean;
}

export function sendJson(
  response: ServerResponse,
  status: number,
  value: unknown,
  options: SendJsonOptions = {},
): boolean {
  if (response.headersSent || response.destroyed) return false;
  const body = `${JSON.stringify(value)}${options.newline === true ? "\n" : ""}`;
  response.statusCode = status;
  if (options.headers !== undefined) {
    for (const [name, headerValue] of Object.entries(options.headers)) {
      if (headerValue !== undefined) response.setHeader(name, headerValue);
    }
  }
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.setHeader("content-length", Buffer.byteLength(body));
  response.setHeader("cache-control", "no-store");
  response.setHeader("x-content-type-options", "nosniff");
  response.end(body);
  return true;
}
