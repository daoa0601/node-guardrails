import { randomUUID } from "node:crypto";
import { readFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { BoundedProcessError, runBoundedProcess } from "../src/process.js";

function run(
  code: string,
  overrides: Partial<{
    readonly maxOutputBytes: number;
    readonly timeoutMs: number;
    readonly killGraceMs: number;
    readonly signal: AbortSignal;
    readonly env: NodeJS.ProcessEnv;
  }> = {},
) {
  return runBoundedProcess({
    executable: process.execPath,
    args: ["-e", code],
    cwd: process.cwd(),
    env: overrides.env ?? { PATH: process.env.PATH },
    stdin: "request-body",
    timeoutMs: overrides.timeoutMs ?? 2_000,
    maxOutputBytes: overrides.maxOutputBytes ?? 1_024,
    ...(overrides.killGraceMs === undefined
      ? {}
      : { killGraceMs: overrides.killGraceMs }),
    ...(overrides.signal === undefined ? {} : { signal: overrides.signal }),
  });
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function readPid(path: string): Promise<number> {
  const deadline = Date.now() + 1_000;
  while (Date.now() < deadline) {
    try {
      const pid = Number(readFileSync(path, "utf8"));
      if (Number.isSafeInteger(pid) && pid > 0) return pid;
    } catch (cause) {
      if ((cause as NodeJS.ErrnoException).code !== "ENOENT") throw cause;
    }
    await delay(5);
  }
  throw new Error(`Timed out waiting for descendant pid at ${path}`);
}

async function waitForFile(path: string): Promise<void> {
  const deadline = Date.now() + 1_000;
  while (Date.now() < deadline) {
    try {
      readFileSync(path);
      return;
    } catch (cause) {
      if ((cause as NodeJS.ErrnoException).code !== "ENOENT") throw cause;
    }
    await delay(5);
  }
  throw new Error(`Timed out waiting for ${path}`);
}

function withDeadline<T>(
  promise: Promise<T>,
  milliseconds: number,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(
        new Error(`Process promise did not settle within ${milliseconds}ms`),
      );
    }, milliseconds);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (cause: unknown) => {
        clearTimeout(timer);
        reject(cause);
      },
    );
  });
}

function killIfRunning(pid: number | undefined): void {
  if (pid === undefined) return;
  try {
    process.kill(pid, "SIGKILL");
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code !== "ESRCH") throw cause;
  }
}

function unlinkIfPresent(path: string): void {
  try {
    unlinkSync(path);
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code !== "ENOENT") throw cause;
  }
}

function descendantFixture(
  afterReady: string,
  inheritOutputPipes: boolean,
): string {
  const descendantCode = `
    const { writeFileSync } = require("node:fs");
    process.on("SIGTERM", () => {});
    writeFileSync(process.env.DESCENDANT_HEARTBEAT_FILE, "ready");
    process.send("ready");
    setInterval(() => {
      writeFileSync(process.env.DESCENDANT_HEARTBEAT_FILE, String(Date.now()));
    }, 20);
    setTimeout(() => process.exit(0), 5_000);
  `;
  return `
    const { spawn } = require("node:child_process");
    const { writeFileSync } = require("node:fs");
    const descendant = spawn(
      process.execPath,
      ["-e", ${JSON.stringify(descendantCode)}],
      {
        stdio: [
          "ignore",
          ${JSON.stringify(inheritOutputPipes ? "inherit" : "ignore")},
          ${JSON.stringify(inheritOutputPipes ? "inherit" : "ignore")},
          "ipc",
        ],
      },
    );
    writeFileSync(process.env.DESCENDANT_PID_FILE, String(descendant.pid));
    descendant.once("message", () => {
      writeFileSync(process.env.DESCENDANT_READY_FILE, "ready");
      ${afterReady}
    });
    setInterval(() => {}, 1_000);
  `;
}

describe("runBoundedProcess", () => {
  it("rejects a pre-aborted signal before reading spawn options", async () => {
    const controller = new AbortController();
    const reason = new Error("already cancelled");
    controller.abort(reason);
    let spawnOptionsRead = false;

    const pending = runBoundedProcess({
      executable: process.execPath,
      args: ["-e", "process.exit(99)"],
      get cwd(): string {
        spawnOptionsRead = true;
        throw new Error("spawn options must not be read");
      },
      timeoutMs: 100,
      maxOutputBytes: 128,
      signal: controller.signal,
    });

    await expect(pending).rejects.toMatchObject({
      kind: "aborted",
      cause: reason,
    });
    expect(spawnOptionsRead).toBe(false);
  });

  it("passes stdin directly and captures both output streams", async () => {
    const result = await run(
      'let body=""; process.stdin.setEncoding("utf8"); process.stdin.on("data", (chunk) => body += chunk); process.stdin.on("end", () => { process.stdout.write(body.toUpperCase()); process.stderr.write("diagnostic"); });',
    );

    expect(result.exitCode).toBe(0);
    expect(result.stdout.toString("utf8")).toBe("REQUEST-BODY");
    expect(result.stderr.toString("utf8")).toBe("diagnostic");
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it.each([
    ["stdout_limit", 'process.stdout.write("x".repeat(2_048))'],
    ["stderr_limit", 'process.stderr.write("x".repeat(2_048))'],
  ] as const)(
    "terminates output with the %s failure kind",
    async (kind, code) => {
      await expect(run(code, { maxOutputBytes: 32 })).rejects.toMatchObject({
        kind,
      });
    },
  );

  it("terminates timed-out and caller-aborted children", async () => {
    await expect(
      run("setInterval(() => {}, 1_000)", { timeoutMs: 20 }),
    ).rejects.toMatchObject({
      kind: "timed_out",
    });

    const controller = new AbortController();
    const pending = run("setInterval(() => {}, 1_000)", {
      signal: controller.signal,
    });
    controller.abort(new Error("stop"));
    await expect(pending).rejects.toMatchObject({ kind: "aborted" });
  });

  it.each([
    ["timed_out", "process.exit(0);", true],
    ["aborted", "", false],
    ["stdout_limit", 'process.stdout.write("x".repeat(2_048));', true],
  ] as const)(
    "settles %s failures and cleans up POSIX descendants",
    async (kind, afterReady, inheritOutputPipes) => {
      const id = `${process.pid}-${randomUUID()}`;
      const pidFile = join(tmpdir(), `node-guardrails-${id}.pid`);
      const readyFile = join(tmpdir(), `node-guardrails-${id}.ready`);
      const heartbeatFile = join(tmpdir(), `node-guardrails-${id}.heartbeat`);
      const controller = new AbortController();
      let descendantPid: number | undefined;
      let pending: ReturnType<typeof run> | undefined;

      try {
        pending = run(descendantFixture(afterReady, inheritOutputPipes), {
          env: {
            PATH: process.env.PATH,
            DESCENDANT_PID_FILE: pidFile,
            DESCENDANT_READY_FILE: readyFile,
            DESCENDANT_HEARTBEAT_FILE: heartbeatFile,
          },
          killGraceMs: 25,
          maxOutputBytes: kind === "stdout_limit" ? 32 : 1_024,
          signal: controller.signal,
          timeoutMs: kind === "timed_out" ? 500 : 2_000,
        });
        descendantPid = await readPid(pidFile);
        await waitForFile(readyFile);
        if (kind === "aborted") controller.abort(new Error("stop"));

        await expect(withDeadline(pending, 1_500)).rejects.toMatchObject({
          kind,
        });

        if (process.platform !== "win32") {
          // Settlement on POSIX must mean the whole isolated group stopped, not merely that the
          // parent-side pipes were destroyed. A live descendant would keep updating this file.
          const heartbeat = readFileSync(heartbeatFile, "utf8");
          await delay(100);
          expect(readFileSync(heartbeatFile, "utf8")).toBe(heartbeat);
        }
        // Windows has no portable process-group kill through Node. The implementation guarantees
        // bounded settlement and direct-child cleanup there; finally below owns descendant cleanup.
      } finally {
        if (descendantPid === undefined) {
          try {
            descendantPid = Number(readFileSync(pidFile, "utf8"));
          } catch {
            // The fixture may have failed before spawning its descendant.
          }
        }
        killIfRunning(descendantPid);
        unlinkIfPresent(pidFile);
        unlinkIfPresent(readyFile);
        unlinkIfPresent(heartbeatFile);
        if (pending !== undefined) {
          await withDeadline(pending, 500).catch(() => undefined);
        }
      }
    },
    5_000,
  );

  it("reports direct launch failures without invoking a shell", async () => {
    const pending = runBoundedProcess({
      executable: "/definitely/not/a/node-guardrails-command",
      args: [],
      cwd: process.cwd(),
      timeoutMs: 100,
      maxOutputBytes: 128,
    });
    await expect(pending).rejects.toBeInstanceOf(BoundedProcessError);
    await expect(pending).rejects.toMatchObject({
      kind: "launch_failed",
      exitCode: null,
    });
  });
});
