import { execFile } from "node:child_process";
import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const packageRoot = fileURLToPath(new URL("..", import.meta.url));
const packageJson = JSON.parse(
  await readFile(path.join(packageRoot, "package.json"), "utf8"),
);
const expectedExports = [".", "./process", "./http", "./cas"];

for (const subpath of expectedExports) {
  const entry = packageJson.exports[subpath];
  if (typeof entry?.import !== "string" || typeof entry?.types !== "string") {
    throw new Error(`Export ${subpath} must declare import and types targets`);
  }
  await access(path.join(packageRoot, entry.import));
  await access(path.join(packageRoot, entry.types));
}

const modules = await Promise.all([
  import("@agentic-orch/node-guardrails"),
  import("@agentic-orch/node-guardrails/process"),
  import("@agentic-orch/node-guardrails/http"),
  import("@agentic-orch/node-guardrails/cas"),
]);
const expectedSymbols = [
  "runBoundedProcess",
  "readBoundedBody",
  "readBoundedJson",
  "matchesBearerToken",
  "sendJson",
  "ContentAddressedFileStore",
];
for (const symbol of expectedSymbols) {
  if (!modules.some((module) => symbol in module)) {
    throw new Error(`Published symbol ${symbol} is missing`);
  }
}

const temporaryRoot = await mkdtemp(
  path.join(os.tmpdir(), "node-guardrails-pack-"),
);
try {
  const packRoot = path.join(temporaryRoot, "pack");
  const consumerRoot = path.join(temporaryRoot, "consumer");
  await Promise.all([mkdir(packRoot), mkdir(consumerRoot)]);
  const { stdout } = await execFileAsync(
    "npm",
    ["pack", "--json", "--pack-destination", packRoot],
    { cwd: packageRoot, encoding: "utf8" },
  );
  const report = JSON.parse(stdout);
  const packed = report[0];
  if (typeof packed?.filename !== "string")
    throw new Error("npm pack did not return a filename");
  const files = new Set(packed.files?.map((entry) => entry.path));
  for (const required of [
    "package.json",
    "LICENSE",
    "README.md",
    "dist/index.js",
    "dist/index.d.ts",
    "dist/process.js",
    "dist/process.d.ts",
    "dist/http.js",
    "dist/http.d.ts",
    "dist/cas.js",
    "dist/cas.d.ts",
  ]) {
    if (!files.has(required))
      throw new Error(`Packed artifact is missing ${required}`);
  }

  await writeFile(
    path.join(consumerRoot, "package.json"),
    `${JSON.stringify({ name: "node-guardrails-pack-smoke", private: true, type: "module" })}\n`,
  );
  const tarball = path.join(packRoot, packed.filename);
  await execFileAsync(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--no-package-lock",
      tarball,
    ],
    { cwd: consumerRoot, encoding: "utf8" },
  );
  await writeFile(
    path.join(consumerRoot, "smoke.mjs"),
    [
      'import { runBoundedProcess } from "@agentic-orch/node-guardrails/process";',
      'import { readBoundedJson } from "@agentic-orch/node-guardrails/http";',
      'import { ContentAddressedFileStore } from "@agentic-orch/node-guardrails/cas";',
      "if (![runBoundedProcess, readBoundedJson, ContentAddressedFileStore].every(Boolean)) process.exitCode = 1;",
      "",
    ].join("\n"),
  );
  await execFileAsync(process.execPath, ["smoke.mjs"], {
    cwd: consumerRoot,
    encoding: "utf8",
  });

  await writeFile(
    path.join(consumerRoot, "types.ts"),
    [
      'import type { BoundedProcessRequest } from "@agentic-orch/node-guardrails/process";',
      'import type { ReadBoundedBodyOptions } from "@agentic-orch/node-guardrails/http";',
      'import type { StoredContent } from "@agentic-orch/node-guardrails/cas";',
      "declare const request: BoundedProcessRequest;",
      "declare const options: ReadBoundedBodyOptions;",
      "declare const stored: StoredContent;",
      "void [request, options, stored];",
      "",
    ].join("\n"),
  );
  await writeFile(
    path.join(consumerRoot, "tsconfig.json"),
    `${JSON.stringify({
      compilerOptions: {
        target: "ES2023",
        module: "NodeNext",
        moduleResolution: "NodeNext",
        strict: true,
        noEmit: true,
        types: ["node"],
        typeRoots: [path.join(packageRoot, "node_modules", "@types")],
        skipLibCheck: true,
      },
      include: ["types.ts"],
    })}\n`,
  );
  await execFileAsync(
    process.execPath,
    [
      path.join(packageRoot, "node_modules", "typescript", "bin", "tsc"),
      "-p",
      "tsconfig.json",
    ],
    { cwd: consumerRoot, encoding: "utf8" },
  );
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
