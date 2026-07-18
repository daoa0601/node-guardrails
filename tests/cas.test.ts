import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { ContentAddressedFileStore } from "../src/cas.js";

const roots: Array<string> = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), "node-guardrails-cas-"));
  roots.push(root);
  return root;
}

describe("ContentAddressedFileStore", () => {
  it("atomically deduplicates and verifies SHA-256 addressed bytes", async () => {
    const root = path.join(await temporaryRoot(), "store");
    const store = new ContentAddressedFileStore({
      root,
      maxBytes: 1_024,
      extension: ".bin",
    });
    const [first, second] = await Promise.all([
      store.stage(Buffer.from("sample")),
      store.stage(Buffer.from("sample")),
    ]);

    expect(second.digest).toBe(first.digest);
    expect(await readFile(path.join(root, `${first.digest}.bin`), "utf8")).toBe("sample");
    const verified = await store.read(first.digest);
    expect(verified.bytes.toString("utf8")).toBe("sample");
  });

  it("rejects empty, oversized, corrupted, and symbolic-link content", async () => {
    const root = await temporaryRoot();
    const store = new ContentAddressedFileStore({
      root: path.join(root, "store"),
      maxBytes: 8,
    });
    await expect(store.stage(Buffer.alloc(0))).rejects.toMatchObject({
      kind: "empty_content",
    });
    await expect(store.stage(Buffer.alloc(9))).rejects.toMatchObject({
      kind: "content_too_large",
    });
    const staged = await store.stage(Buffer.from("sample"));
    const storedPath = path.join(root, "store", staged.digest);
    await writeFile(storedPath, "changed");
    await expect(store.read(staged.digest)).rejects.toMatchObject({
      kind: "digest_mismatch",
    });
    await rm(storedPath);
    await symlink("/dev/null", storedPath);
    await expect(store.read(staged.digest)).rejects.toMatchObject({
      kind: "invalid_file",
    });
  });

  it("opens source files without following symbolic links", async () => {
    const root = await temporaryRoot();
    const source = path.join(root, "source");
    const symbolic = path.join(root, "symbolic");
    await writeFile(source, "source");
    await symlink(source, symbolic);
    const store = new ContentAddressedFileStore({
      root: path.join(root, "store"),
      maxBytes: 32,
    });

    await expect(store.stageFile(symbolic)).rejects.toMatchObject({
      kind: "invalid_file",
    });
    await expect(store.stageFile(source, 3)).rejects.toMatchObject({
      kind: "content_too_large",
    });
    await expect(store.stageFile(source)).resolves.toMatchObject({ size: 6 });
  });

  it("returns bytes that stay verified after the backing pathname is replaced", async () => {
    const root = await temporaryRoot();
    const store = new ContentAddressedFileStore({
      root: path.join(root, "store"),
      maxBytes: 32,
    });
    const staged = await store.stage(Buffer.from("trusted"));
    const storedPath = path.join(root, "store", staged.digest);

    const verified = await store.read(staged.digest);
    await unlink(storedPath);
    await writeFile(storedPath, "attacker", { mode: 0o600 });

    expect(verified.bytes.toString()).toBe("trusted");
    await expect(store.read(staged.digest)).rejects.toMatchObject({
      kind: "digest_mismatch",
    });
  });

  it("snapshots caller-owned bytes before awaiting and does not poison a digest", async () => {
    const root = await temporaryRoot();
    const store = new ContentAddressedFileStore({
      root: path.join(root, "store"),
      maxBytes: 32,
    });
    const mutable = Buffer.from("original");

    const stagedPromise = store.stage(mutable);
    mutable.fill("x");
    const staged = await stagedPromise;

    expect((await store.read(staged.digest)).bytes.toString()).toBe("original");
    await expect(store.stage(Buffer.from("original"))).resolves.toMatchObject({
      digest: staged.digest,
    });
  });

  it("detects root rebinding and permission drift around pathname operations", async () => {
    const root = await temporaryRoot();
    const parent = path.join(root, "parent");
    const attacker = path.join(root, "attacker");
    await Promise.all([mkdir(parent, { mode: 0o700 }), mkdir(attacker, { mode: 0o700 })]);
    const store = new ContentAddressedFileStore({
      root: path.join(parent, "store"),
      maxBytes: 32,
    });
    const staged = await store.stage(Buffer.from("trusted"));

    await rename(parent, `${parent}-original`);
    await mkdir(path.join(attacker, "store"), { mode: 0o700 });
    await writeFile(
      path.join(attacker, "store", staged.digest),
      "trusted",
      { mode: 0o600 },
    );
    await symlink(attacker, parent);
    await expect(store.read(staged.digest)).rejects.toMatchObject({ kind: "invalid_root" });

    await unlink(parent);
    await rename(`${parent}-original`, parent);
    await chmod(path.join(parent, "store"), 0o755);
    await expect(store.read(staged.digest)).rejects.toMatchObject({ kind: "invalid_root" });
  });

  it("rejects untrusted root symlinks and corrupt destinations until explicitly repaired", async () => {
    const root = await temporaryRoot();
    const target = path.join(root, "target");
    const symbolic = path.join(root, "symbolic");
    await mkdir(target, { mode: 0o700 });
    await symlink(target, symbolic);
    const symbolicStore = new ContentAddressedFileStore({ root: symbolic, maxBytes: 32 });
    await expect(symbolicStore.initialize()).rejects.toMatchObject({ kind: "invalid_root" });

    const store = new ContentAddressedFileStore({
      root: path.join(root, "store"),
      maxBytes: 32,
    });
    const correct = await store.stage(Buffer.from("correct"));
    const correctPath = path.join(root, "store", correct.digest);
    await writeFile(correctPath, "corrupt", { mode: 0o600 });
    await expect(store.stage(Buffer.from("correct"))).rejects.toMatchObject({
      kind: "digest_mismatch",
    });
    await unlink(correctPath);
    await expect(store.stage(Buffer.from("correct"))).resolves.toMatchObject({
      digest: correct.digest,
    });
    expect(await readFile(correctPath, "utf8")).toBe("correct");
  });
});
