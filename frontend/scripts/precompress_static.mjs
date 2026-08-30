#!/usr/bin/env node

import {
  brotliCompress,
  constants,
  gzip,
} from "node:zlib";
import {
  mkdir,
  readdir,
  readFile,
  rename,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import {
  dirname,
  extname,
  isAbsolute,
  join,
  normalize,
  relative,
} from "node:path";
import { promisify } from "node:util";

const brotli = promisify(brotliCompress);
const gzipAsync = promisify(gzip);
const staticRoot = process.env.NUMOJ_STATIC_ROOT || "public/static";
const minimumBytes = 100 * 1024;
const compressibleExtensions = new Set([".css", ".html", ".js", ".json", ".svg"]);
const manifestPath = process.env.NUMOJ_PRECOMPRESS_MANIFEST || "";

async function collect(directory) {
  const sources = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      sources.push(...await collect(path));
    } else if (
      entry.isFile()
      && compressibleExtensions.has(extname(entry.name))
      && (await stat(path)).size >= minimumBytes
    ) {
      sources.push(path);
    }
  }
  return sources;
}

async function atomicWrite(path, bytes) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}`;
  await writeFile(temporary, bytes, { mode: 0o644 });
  await rename(temporary, path);
}

function managedSidecarPath(value) {
  if (typeof value !== "string" || isAbsolute(value)) return null;
  const normalized = normalize(value);
  if (
    normalized.startsWith("..")
    || (!normalized.endsWith(".br") && !normalized.endsWith(".gz"))
  ) {
    return null;
  }
  const path = join(staticRoot, normalized);
  return relative(staticRoot, path).startsWith("..") ? null : path;
}

async function readManagedSidecars() {
  if (!manifestPath) return [];
  try {
    const payload = JSON.parse(await readFile(manifestPath, "utf8"));
    if (!payload || payload.version !== 1 || !Array.isArray(payload.sidecars)) {
      throw new Error("manifest schema mismatch");
    }
    return payload.sidecars;
  } catch (error) {
    if (error && error.code === "ENOENT") return [];
    throw new Error(`无法读取预压缩资源清单 ${manifestPath}: ${error.message}`);
  }
}

function makeGzipPortable(bytes) {
  if (
    bytes.length < 10
    || bytes[0] !== 0x1f
    || bytes[1] !== 0x8b
    || bytes[2] !== 0x08
  ) {
    throw new Error("zlib returned an invalid gzip stream");
  }
  // RFC 1952 的第 10 字节只是创建端操作系统标识，不参与解压。Node/zlib
  // 会在 macOS 写 19、Linux 写 3，导致同一源文件在 ARM Mac 和 GitHub x64
  // runner 上产生一字节漂移。统一写 unknown(255)，保留压缩流和校验值不变。
  bytes[9] = 0xff;
  return bytes;
}

const sources = await collect(staticRoot);
const expectedSidecars = new Set(
  sources.flatMap((path) => [`${path}.br`, `${path}.gz`]),
);
let rawBytes = 0;
let compressedBytes = 0;
for (const path of sources) {
  const source = await readFile(path);
  const [brotliBytes, nativeGzipBytes] = await Promise.all([
    brotli(source, {
      params: {
        [constants.BROTLI_PARAM_QUALITY]: 11,
        [constants.BROTLI_PARAM_MODE]: constants.BROTLI_MODE_TEXT,
      },
    }),
    gzipAsync(source, { level: 9 }),
  ]);
  const gzipBytes = makeGzipPortable(nativeGzipBytes);
  await Promise.all([
    atomicWrite(`${path}.br`, brotliBytes),
    atomicWrite(`${path}.gz`, gzipBytes),
  ]);
  rawBytes += source.length;
  compressedBytes += brotliBytes.length;
  console.log(`${path}: ${source.length} -> br ${brotliBytes.length}, gzip ${gzipBytes.length}`);
}
let removedManagedSidecars = 0;
for (const entry of await readManagedSidecars()) {
  const path = managedSidecarPath(entry);
  if (path && !expectedSidecars.has(path)) {
    try {
      await unlink(path);
      removedManagedSidecars += 1;
    } catch (error) {
      if (!error || error.code !== "ENOENT") throw error;
    }
  }
}
if (manifestPath) {
  const sidecars = [...expectedSidecars]
    .map((path) => relative(staticRoot, path))
    .sort();
  await atomicWrite(
    manifestPath,
    Buffer.from(`${JSON.stringify({ version: 1, sidecars }, null, 2)}\n`),
  );
}
console.log(
  `precompressed ${sources.length} assets: ${rawBytes} raw bytes -> ${compressedBytes} Brotli bytes; removed ${removedManagedSidecars} managed orphaned sidecars`,
);
