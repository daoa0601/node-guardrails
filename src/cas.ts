import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  link,
  lstat,
  mkdir,
  open,
  realpath,
  unlink,
} from "node:fs/promises";
import type { BigIntStats } from "node:fs";
import type { FileHandle } from "node:fs/promises";
import path from "node:path";

const SHA256 = /^[a-f0-9]{64}$/u;
const EXTENSION = /^\.[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/u;
const READ_CHUNK_BYTES = 64 * 1024;

export type ContentAddressedStoreFailureKind =
  | "content_too_large"
  | "digest_mismatch"
  | "empty_content"
  | "invalid_digest"
  | "invalid_file"
  | "invalid_root"
  | "io_error"
  | "not_found";

export class ContentAddressedStoreError extends Error {
  readonly kind: ContentAddressedStoreFailureKind;

  constructor(options: {
    readonly kind: ContentAddressedStoreFailureKind;
    readonly message: string;
    readonly cause?: unknown;
  }) {
    super(
      options.message,
      options.cause === undefined ? undefined : { cause: options.cause },
    );
    this.name = "ContentAddressedStoreError";
    this.kind = options.kind;
  }
}

export interface ContentAddressedFileStoreOptions {
  readonly root: string;
  readonly maxBytes: number;
  readonly extension?: string;
  readonly allowEmpty?: boolean;
}

export interface StoredContent {
  readonly digest: string;
  readonly size: number;
}

export interface VerifiedContent extends StoredContent {
  /** The exact bounded bytes that were SHA-256 verified through the opened file handle. */
  readonly bytes: Buffer;
}

interface DirectoryIdentity {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly uid: bigint;
}

function nodeCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String(error.code)
    : undefined;
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function sameIdentity(info: BigIntStats, identity: DirectoryIdentity): boolean {
  return info.dev === identity.dev && info.ino === identity.ino;
}

function effectiveUid(): bigint | undefined {
  return typeof process.geteuid === "function" ? BigInt(process.geteuid()) : undefined;
}

function absolutePrefixes(value: string): ReadonlyArray<string> {
  const parsed = path.parse(value);
  const relative = value.slice(parsed.root.length);
  const parts = relative.split(path.sep).filter((part) => part.length > 0);
  const prefixes = [parsed.root];
  let current = parsed.root;
  for (const part of parts) {
    current = path.join(current, part);
    prefixes.push(current);
  }
  return prefixes;
}

function rootFailure(message: string, cause?: unknown): ContentAddressedStoreError {
  return new ContentAddressedStoreError({ kind: "invalid_root", message, cause });
}

/**
 * A bounded file CAS for a namespace private to one trusted OS identity.
 *
 * Portable Node.js has no descriptor-relative openat/linkat API. Identity checks therefore detect
 * persistent root/ancestor rebinding but cannot exclude a precisely timed swap-and-restore. Code
 * running as the same effective UID, root/admin, ACL or mount controllers, and filesystems without
 * stable POSIX device/inode semantics are inside the trust boundary. read() still binds returned
 * bytes to the requested digest even if the pathname changes after the handle closes.
 */
export class ContentAddressedFileStore {
  readonly root: string;
  readonly maxBytes: number;
  readonly extension: string;
  readonly allowEmpty: boolean;

  #canonicalRoot: string | undefined;
  #identity: DirectoryIdentity | undefined;
  #initialization: Promise<void> | undefined;

  constructor(options: ContentAddressedFileStoreOptions) {
    if (!Number.isSafeInteger(options.maxBytes) || options.maxBytes <= 0) {
      throw new TypeError("maxBytes must be a positive safe integer");
    }
    const extension = options.extension ?? "";
    if (extension !== "" && !EXTENSION.test(extension)) {
      throw new TypeError(
        "extension must be a simple dot-prefixed file extension",
      );
    }
    this.root = path.resolve(options.root);
    this.maxBytes = options.maxBytes;
    this.extension = extension;
    this.allowEmpty = options.allowEmpty ?? false;
  }

  async initialize(): Promise<void> {
    this.#initialization ??= this.#initializeRoot().catch((cause: unknown) => {
      this.#initialization = undefined;
      throw cause;
    });
    await this.#initialization;
    await this.#assertRootIdentity();
  }

  async stage(bytes: Uint8Array): Promise<StoredContent> {
    // Copy before the first await. The caller may mutate a Uint8Array (including one backed by a
    // SharedArrayBuffer) as soon as this method returns its promise.
    const snapshot = Buffer.from(bytes);
    this.#validateSize(snapshot.byteLength);
    const digest = sha256(snapshot);
    await this.initialize();
    const destination = this.#file(digest);
    const temporary = path.join(
      this.#requiredRoot(),
      `.${digest}.${randomUUID()}.tmp`,
    );
    let temporaryHandle: FileHandle | undefined;
    let rootIsCurrent = true;
    try {
      await this.#assertRootIdentity();
      temporaryHandle = await open(
        temporary,
        constants.O_CREAT |
          constants.O_EXCL |
          constants.O_RDWR |
          constants.O_NOFOLLOW,
        0o600,
      );
      await temporaryHandle.writeFile(snapshot);
      const written = await this.#readStableFile(temporaryHandle, this.maxBytes);
      if (written.byteLength !== snapshot.byteLength || sha256(written) !== digest) {
        throw new ContentAddressedStoreError({
          kind: "digest_mismatch",
          message: "Staged content changed before atomic publication",
        });
      }
      await this.#assertRootIdentity();
      try {
        await link(temporary, destination);
      } catch (cause) {
        if (nodeCode(cause) !== "EEXIST") throw cause;
      }
      await this.#assertRootIdentity();
    } catch (cause) {
      rootIsCurrent = await this.#rootIsCurrent();
      if (cause instanceof ContentAddressedStoreError) throw cause;
      throw new ContentAddressedStoreError({
        kind: "io_error",
        message: "Unable to stage content-addressed data",
        cause,
      });
    } finally {
      await temporaryHandle?.close().catch(() => undefined);
      // Never clean up by pathname after detecting that the trusted root name was rebound.
      if (rootIsCurrent) await unlink(temporary).catch(() => undefined);
    }
    return this.inspect(digest);
  }

  async stageFile(
    file: string,
    maximum = this.maxBytes,
  ): Promise<StoredContent> {
    const boundedMaximum = this.#maximum(maximum);
    let handle: FileHandle | undefined;
    try {
      handle = await open(
        path.resolve(file),
        constants.O_RDONLY | constants.O_NOFOLLOW,
      );
      const info = await handle.stat({ bigint: true });
      if (!info.isFile()) {
        throw new ContentAddressedStoreError({
          kind: "invalid_file",
          message: "Content source must be a regular file",
        });
      }
      this.#validateSize(Number(info.size), boundedMaximum);
      const bytes = await this.#readStableFile(handle, boundedMaximum);
      return await this.stage(bytes);
    } catch (cause) {
      if (cause instanceof ContentAddressedStoreError) throw cause;
      throw new ContentAddressedStoreError({
        kind: "invalid_file",
        message: "Unable to read a regular content source file",
        cause,
      });
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }

  async read(digest: string, maximum = this.maxBytes): Promise<VerifiedContent> {
    this.#validateDigest(digest);
    const boundedMaximum = this.#maximum(maximum);
    await this.initialize();
    const candidate = this.#file(digest);
    let handle: FileHandle | undefined;
    try {
      await this.#assertRootIdentity();
      handle = await open(candidate, constants.O_RDONLY | constants.O_NOFOLLOW);
      await this.#assertRootIdentity();
      const info = await handle.stat({ bigint: true });
      if (!info.isFile()) {
        throw new ContentAddressedStoreError({
          kind: "invalid_file",
          message: "Content-addressed path is not a regular file",
        });
      }
      this.#validateStoredFilePolicy(info);
      this.#validateSize(Number(info.size), boundedMaximum);
      const bytes = await this.#readStableFile(handle, boundedMaximum);
      if (sha256(bytes) !== digest) {
        throw new ContentAddressedStoreError({
          kind: "digest_mismatch",
          message: "Content-addressed file failed SHA-256 verification",
        });
      }
      await this.#assertRootIdentity();
      return { digest, size: bytes.byteLength, bytes };
    } catch (cause) {
      if (cause instanceof ContentAddressedStoreError) throw cause;
      const code = nodeCode(cause);
      throw new ContentAddressedStoreError({
        kind: code === "ENOENT" ? "not_found" : "invalid_file",
        message:
          code === "ENOENT"
            ? "Content-addressed file is unavailable"
            : "Unable to verify the content-addressed file",
        cause,
      });
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }

  async inspect(digest: string): Promise<StoredContent> {
    const { bytes: _bytes, ...stored } = await this.read(digest);
    return stored;
  }

  async #initializeRoot(): Promise<void> {
    try {
      await this.#rejectUntrustedLexicalSymlinks();
      const creation = await this.#canonicalCreationPath();
      await this.#validateAncestors(creation.parent);
      await mkdir(creation.target, { recursive: true, mode: 0o700 });
      const canonical = await realpath(creation.target);
      if (canonical !== creation.target) {
        throw rootFailure("Content-addressed store root must not contain mutable symlinks");
      }
      const handle = await open(
        canonical,
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
      );
      try {
        const info = await handle.stat({ bigint: true });
        this.#validateRootPolicy(info);
        this.#canonicalRoot = canonical;
        this.#identity = { dev: info.dev, ino: info.ino, uid: info.uid };
      } finally {
        await handle.close();
      }
      await this.#validateAncestors(canonical);
    } catch (cause) {
      if (cause instanceof ContentAddressedStoreError) throw cause;
      throw rootFailure("Unable to initialize the content-addressed store", cause);
    }
  }

  async #canonicalCreationPath(): Promise<{
    readonly parent: string;
    readonly target: string;
  }> {
    let existing = this.root;
    const missing: Array<string> = [];
    for (;;) {
      try {
        const info = await lstat(existing, { bigint: true });
        const canonicalParent = await realpath(existing);
        const canonicalInfo = await lstat(canonicalParent, { bigint: true });
        if (
          (!info.isDirectory() && !info.isSymbolicLink()) ||
          !canonicalInfo.isDirectory() ||
          canonicalInfo.isSymbolicLink()
        ) {
          throw rootFailure("Content-addressed store ancestry must contain only directories");
        }
        return {
          parent: canonicalParent,
          target: path.join(canonicalParent, ...missing),
        };
      } catch (cause) {
        if (cause instanceof ContentAddressedStoreError) throw cause;
        if (nodeCode(cause) !== "ENOENT") throw cause;
        const parent = path.dirname(existing);
        if (parent === existing) throw cause;
        missing.unshift(path.basename(existing));
        existing = parent;
      }
    }
  }

  async #rejectUntrustedLexicalSymlinks(): Promise<void> {
    const uid = effectiveUid();
    for (const prefix of absolutePrefixes(this.root)) {
      let info: BigIntStats;
      try {
        info = await lstat(prefix, { bigint: true });
      } catch (cause) {
        if (nodeCode(cause) === "ENOENT") return;
        throw cause;
      }
      if (!info.isSymbolicLink()) continue;
      if (prefix === this.root || (uid !== undefined && info.uid !== 0n)) {
        throw rootFailure("Content-addressed store ancestry contains an untrusted symbolic link");
      }
    }
  }

  async #validateAncestors(value: string): Promise<void> {
    const uid = effectiveUid();
    for (const prefix of absolutePrefixes(value)) {
      const info = await lstat(prefix, { bigint: true });
      if (!info.isDirectory() || info.isSymbolicLink()) {
        throw rootFailure("Content-addressed store ancestry must contain only real directories");
      }
      if (uid !== undefined && info.uid !== uid && info.uid !== 0n) {
        throw rootFailure("Content-addressed store ancestry has an untrusted owner");
      }
      const writableByOthers = (info.mode & 0o022n) !== 0n;
      const sticky = (info.mode & 0o1000n) !== 0n;
      if (writableByOthers && !sticky) {
        throw rootFailure("Content-addressed store ancestry is writable by another account");
      }
    }
  }

  #validateRootPolicy(info: BigIntStats): void {
    const uid = effectiveUid();
    if (!info.isDirectory() || info.isSymbolicLink()) {
      throw rootFailure("Content-addressed store root must be a real directory");
    }
    if (uid !== undefined && info.uid !== uid) {
      throw rootFailure("Content-addressed store root must be owned by the effective user");
    }
    if ((info.mode & 0o077n) !== 0n) {
      throw rootFailure("Content-addressed store root permissions must be private");
    }
  }

  #validateStoredFilePolicy(info: BigIntStats): void {
    const identity = this.#requiredIdentity();
    if (info.dev !== identity.dev) {
      throw new ContentAddressedStoreError({
        kind: "invalid_file",
        message: "Content-addressed file is on an unexpected device",
      });
    }
    if (info.uid !== identity.uid || (info.mode & 0o022n) !== 0n) {
      throw new ContentAddressedStoreError({
        kind: "invalid_file",
        message: "Content-addressed file ownership or permissions are unsafe",
      });
    }
  }

  async #assertRootIdentity(): Promise<void> {
    const root = this.#requiredRoot();
    const identity = this.#requiredIdentity();
    let handle: FileHandle | undefined;
    try {
      handle = await open(
        root,
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
      );
      const info = await handle.stat({ bigint: true });
      this.#validateRootPolicy(info);
      if (!sameIdentity(info, identity)) {
        throw rootFailure("Content-addressed store root identity changed");
      }
    } catch (cause) {
      if (cause instanceof ContentAddressedStoreError) throw cause;
      throw rootFailure("Unable to revalidate the content-addressed store root", cause);
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }

  async #rootIsCurrent(): Promise<boolean> {
    try {
      await this.#assertRootIdentity();
      return true;
    } catch {
      return false;
    }
  }

  async #readStableFile(handle: FileHandle, maximum: number): Promise<Buffer> {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()) {
      throw new ContentAddressedStoreError({
        kind: "invalid_file",
        message: "Content source must be a regular file",
      });
    }
    this.#validateSize(Number(before.size), maximum);
    const chunks: Array<Buffer> = [];
    let total = 0;
    for (;;) {
      const capacity = Math.min(READ_CHUNK_BYTES, maximum - total + 1);
      const chunk = Buffer.allocUnsafe(capacity);
      const { bytesRead } = await handle.read(chunk, 0, capacity, total);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maximum) this.#validateSize(total, maximum);
      chunks.push(chunk.subarray(0, bytesRead));
    }
    const after = await handle.stat({ bigint: true });
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs ||
      BigInt(total) !== after.size
    ) {
      throw new ContentAddressedStoreError({
        kind: "invalid_file",
        message: "Content source changed while it was being read",
      });
    }
    return Buffer.concat(chunks, total);
  }

  #validateDigest(digest: string): void {
    if (!SHA256.test(digest)) {
      throw new ContentAddressedStoreError({
        kind: "invalid_digest",
        message: "SHA-256 digest is invalid",
      });
    }
  }

  #file(digest: string): string {
    return path.join(this.#requiredRoot(), `${digest}${this.extension}`);
  }

  #maximum(maximum: number): number {
    if (!Number.isSafeInteger(maximum) || maximum <= 0) {
      throw new TypeError("maximum must be a positive safe integer");
    }
    return Math.min(maximum, this.maxBytes);
  }

  #validateSize(size: number, maximum = this.maxBytes): void {
    if (!Number.isSafeInteger(size) || size < 0) {
      throw new ContentAddressedStoreError({
        kind: "invalid_file",
        message: "Content size is invalid",
      });
    }
    if (!this.allowEmpty && size === 0) {
      throw new ContentAddressedStoreError({
        kind: "empty_content",
        message: "Content must not be empty",
      });
    }
    if (size > maximum || size > this.maxBytes) {
      throw new ContentAddressedStoreError({
        kind: "content_too_large",
        message: `Content exceeds the ${Math.min(maximum, this.maxBytes)}-byte limit`,
      });
    }
  }

  #requiredRoot(): string {
    if (this.#canonicalRoot === undefined) {
      throw rootFailure("Content-addressed store is not initialized");
    }
    return this.#canonicalRoot;
  }

  #requiredIdentity(): DirectoryIdentity {
    if (this.#identity === undefined) {
      throw rootFailure("Content-addressed store is not initialized");
    }
    return this.#identity;
  }
}
