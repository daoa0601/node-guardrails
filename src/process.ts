import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";

export type BoundedProcessFailureKind =
  "aborted" | "launch_failed" | "stderr_limit" | "stdout_limit" | "timed_out";

export interface BoundedProcessRequest {
  readonly executable: string;
  readonly args: ReadonlyArray<string>;
  readonly cwd: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly stdin?: string | Uint8Array;
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  readonly killGraceMs?: number;
  readonly signal?: AbortSignal;
}

export interface BoundedProcessResult {
  readonly exitCode: number;
  readonly stdout: Buffer;
  readonly stderr: Buffer;
  readonly durationMs: number;
}

export class BoundedProcessError extends Error {
  readonly kind: BoundedProcessFailureKind;
  readonly executable: string;
  readonly stdout: Buffer;
  readonly stderr: Buffer;
  readonly exitCode: number | null;
  readonly signalCode: NodeJS.Signals | null;

  constructor(options: {
    readonly kind: BoundedProcessFailureKind;
    readonly message: string;
    readonly executable: string;
    readonly stdout?: Buffer;
    readonly stderr?: Buffer;
    readonly exitCode?: number | null;
    readonly signalCode?: NodeJS.Signals | null;
    readonly cause?: unknown;
  }) {
    super(
      options.message,
      options.cause === undefined ? undefined : { cause: options.cause },
    );
    this.name = "BoundedProcessError";
    this.kind = options.kind;
    this.executable = options.executable;
    this.stdout = options.stdout ?? Buffer.alloc(0);
    this.stderr = options.stderr ?? Buffer.alloc(0);
    this.exitCode = options.exitCode ?? null;
    this.signalCode = options.signalCode ?? null;
  }
}

function positiveInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${name} must be a positive safe integer`);
  }
}

const canTerminateProcessGroups = process.platform !== "win32";

/**
 * Executes one program directly, never through a shell, with independently bounded stdout and
 * stderr. Timeout, caller cancellation, and output-limit failures terminate the child before the
 * returned promise settles.
 */
export function runBoundedProcess(
  request: BoundedProcessRequest,
): Promise<BoundedProcessResult> {
  positiveInteger(request.timeoutMs, "timeoutMs");
  positiveInteger(request.maxOutputBytes, "maxOutputBytes");
  const killGraceMs = request.killGraceMs ?? 2_000;
  positiveInteger(killGraceMs, "killGraceMs");
  if (request.executable.length === 0)
    throw new TypeError("executable must not be empty");

  // Do not launch a process that the caller has already cancelled. In particular, keep this
  // check ahead of reading spawn-only request fields such as env and cwd.
  if (request.signal?.aborted === true) {
    return Promise.reject(
      new BoundedProcessError({
        kind: "aborted",
        message: "Process execution was aborted",
        executable: request.executable,
        cause: request.signal.reason,
      }),
    );
  }

  return new Promise<BoundedProcessResult>((resolve, reject) => {
    const started = performance.now();
    const stdout: Array<Buffer> = [];
    const stderr: Array<Buffer> = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let terminalError: BoundedProcessError | undefined;
    let forceKillTimer: NodeJS.Timeout | undefined;
    let groupPollTimer: NodeJS.Timeout | undefined;
    let settlementTimer: NodeJS.Timeout | undefined;
    let observedClose:
      | {
          readonly exitCode: number | null;
          readonly signalCode: NodeJS.Signals | null;
        }
      | undefined;
    let settled = false;
    let child: ChildProcessWithoutNullStreams;

    const captured = (): {
      readonly stdout: Buffer;
      readonly stderr: Buffer;
    } => ({
      stdout: Buffer.concat(stdout, stdoutBytes),
      stderr: Buffer.concat(stderr, stderrBytes),
    });

    try {
      child = spawn(request.executable, [...request.args], {
        cwd: request.cwd,
        env: request.env ?? process.env,
        shell: false,
        // POSIX detached children lead a new session/process group. This lets failure cleanup
        // reach descendants that inherited these pipes. Windows has no portable killpg(2)
        // equivalent in Node, so it deliberately falls back to terminating only the direct child.
        detached: canTerminateProcessGroups,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (cause) {
      reject(
        new BoundedProcessError({
          kind: "launch_failed",
          message: `Unable to launch ${request.executable}`,
          executable: request.executable,
          cause,
        }),
      );
      return;
    }

    const signalProcessTree = (signal: NodeJS.Signals): void => {
      try {
        if (canTerminateProcessGroups && child.pid !== undefined) {
          // Do not skip this when the group leader has exited: a descendant may still belong to
          // the group and keep an inherited stdout or stderr descriptor open.
          process.kill(-child.pid, signal);
        } else if (child.exitCode === null && child.signalCode === null) {
          child.kill(signal);
        }
      } catch {
        // The process or group may have exited between the state check and signal delivery.
      }
    };

    const processGroupIsAlive = (): boolean => {
      if (!canTerminateProcessGroups || child.pid === undefined) return false;
      try {
        process.kill(-child.pid, 0);
        return true;
      } catch (cause) {
        // Only ESRCH proves that no member remains. Permission errors and unexpected platform
        // failures are treated conservatively as alive until the bounded settlement deadline.
        return (cause as NodeJS.ErrnoException).code !== "ESRCH";
      }
    };

    const settle = (
      exitCode: number | null,
      signalCode: NodeJS.Signals | null,
    ): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (forceKillTimer !== undefined) clearTimeout(forceKillTimer);
      if (groupPollTimer !== undefined) clearTimeout(groupPollTimer);
      if (settlementTimer !== undefined) clearTimeout(settlementTimer);
      request.signal?.removeEventListener("abort", abort);
      const output = captured();
      if (terminalError !== undefined) {
        reject(
          new BoundedProcessError({
            kind: terminalError.kind,
            message: terminalError.message,
            executable: request.executable,
            stdout: output.stdout,
            stderr: output.stderr,
            // spawn(2) failures do not have a meaningful process exit status. Node reports an
            // internal negative close code for ENOENT on some platforms; do not expose it.
            exitCode: terminalError.kind === "launch_failed" ? null : exitCode,
            signalCode,
            cause: terminalError.cause,
          }),
        );
        return;
      }
      resolve({
        exitCode: exitCode ?? (signalCode === null ? 1 : 128),
        stdout: output.stdout,
        stderr: output.stderr,
        durationMs: Math.round(performance.now() - started),
      });
    };

    const terminate = (): void => {
      signalProcessTree("SIGTERM");
      forceKillTimer ??= setTimeout(() => {
        signalProcessTree("SIGKILL");

        // A descendant can outlive the direct child and retain its inherited pipe handles. POSIX
        // cleanup above kills the whole group; on Windows this stream teardown is the bounded
        // fallback and descendants outside our control may continue running. Destroying our pipe
        // endpoints ensures their lifetime cannot prevent this promise from settling.
        child.stdin.destroy();
        child.stdout.destroy();
        child.stderr.destroy();

        // Signal delivery is asynchronous. On POSIX, do not equate sending SIGKILL with proving
        // that the isolated group is gone; poll for ESRCH while a final referenced deadline keeps
        // settlement bounded even if the platform never reports closure.
        settlementTimer ??= setTimeout(() => {
          settle(child.exitCode, child.signalCode);
        }, killGraceMs);

        const settleWhenClean = (): void => {
          if (settled) return;
          if (observedClose !== undefined && !processGroupIsAlive()) {
            settle(observedClose.exitCode, observedClose.signalCode);
            return;
          }
          groupPollTimer = setTimeout(
            settleWhenClean,
            Math.max(1, Math.min(10, killGraceMs)),
          );
          groupPollTimer.unref();
        };
        settleWhenClean();
      }, killGraceMs);
    };

    const failAfterClose = (
      kind: BoundedProcessFailureKind,
      message: string,
      cause?: unknown,
    ): void => {
      if (terminalError !== undefined) return;
      const output = captured();
      terminalError = new BoundedProcessError({
        kind,
        message,
        executable: request.executable,
        stdout: output.stdout,
        stderr: output.stderr,
        cause,
      });
      terminate();
    };

    const abort = (): void => {
      failAfterClose(
        "aborted",
        "Process execution was aborted",
        request.signal?.reason,
      );
    };
    if (request.signal?.aborted === true) abort();
    else request.signal?.addEventListener("abort", abort, { once: true });

    const timeout = setTimeout(() => {
      failAfterClose(
        "timed_out",
        `Process timed out after ${request.timeoutMs} milliseconds`,
      );
    }, request.timeoutMs);
    timeout.unref();

    child.stdout.on("data", (raw: Buffer | string) => {
      const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
      if (stdoutBytes + chunk.byteLength > request.maxOutputBytes) {
        failAfterClose(
          "stdout_limit",
          `Process stdout exceeded ${request.maxOutputBytes} bytes`,
        );
        return;
      }
      stdoutBytes += chunk.byteLength;
      stdout.push(chunk);
    });
    child.stderr.on("data", (raw: Buffer | string) => {
      const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
      if (stderrBytes + chunk.byteLength > request.maxOutputBytes) {
        failAfterClose(
          "stderr_limit",
          `Process stderr exceeded ${request.maxOutputBytes} bytes`,
        );
        return;
      }
      stderrBytes += chunk.byteLength;
      stderr.push(chunk);
    });
    child.once("error", (cause) => {
      if (child.pid === undefined) {
        // No child exists whose streams, descendants, or exit event need to be awaited. Preserve
        // an earlier cancellation if one won the race; otherwise report the spawn failure with a
        // null exitCode instead of Node's internal negative close status for ENOENT.
        if (terminalError === undefined) {
          terminalError = new BoundedProcessError({
            kind: "launch_failed",
            message: `Unable to launch ${request.executable}`,
            executable: request.executable,
            cause,
          });
        }
        settle(null, null);
        return;
      }
      // A post-spawn ChildProcess error is not proof that the child or its process group exited.
      // Keep the first terminal cause and complete the normal TERM/KILL custody path.
      failAfterClose(
        "launch_failed",
        `Unable to launch ${request.executable}`,
        cause,
      );
    });
    child.once("close", (exitCode, signalCode) => {
      observedClose = { exitCode, signalCode };
      // A group member may outlive the leader after closing or redirecting inherited pipes. Do not
      // settle a failure until POSIX confirms ESRCH; the force/final timers own escalation and the
      // bounded fallback. Windows has no group to confirm and can settle once the direct child closes.
      if (terminalError !== undefined && processGroupIsAlive()) {
        return;
      }
      settle(exitCode, signalCode);
    });
    child.stdin.on("error", () => {
      // A fast-failing child may close stdin before consuming its bounded request.
    });
    child.stdin.end(request.stdin ?? "");
  });
}
