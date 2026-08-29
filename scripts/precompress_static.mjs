#!/usr/bin/env node

import {
  brotliCompress,
  constants,
  gzip,
} from "node:zlib";
import {
  readdir,
  readFile,
  rename,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { extname, join } from "node:path";
import { promisify } from "node:util";

const brotli = promisify(brotliCompress);
const gzipAsync = promisify(gzip);
const staticRoot = "static";
const minimumBytes = 100 * 1024;
const compressibleExtensions = new Set([".css", ".html", ".js", ".json", ".svg"]);

async function collect(directory) {
  const sources = [];
  const sidecars = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      const nested = await collect(path);
      sources.push(...nested.sources);
      sidecars.push(...nested.sidecars);
    } else if (
      entry.isFile()
      && (entry.name.endsWith(".br") || entry.name.endsWith(".gz"))
    ) {
      sidecars.push(path);
    } else if (
      entry.isFile()
      && compressibleExtensions.has(extname(entry.name))
      && (await stat(path)).size >= minimumBytes
    ) {
      sources.push(path);
    }
  }
  return { sources, sidecars };
}

async function atomicWrite(path, bytes) {
  const temporary = `${path}.tmp-${process.pid}`;
  await writeFile(temporary, bytes, { mode: 0o644 });
  await rename(temporary, path);
}

const { sources, sidecars } = await collect(staticRoot);
const expectedSidecars = new Set(
  sources.flatMap((path) => [`${path}.br`, `${path}.gz`]),
);
let rawBytes = 0;
let compressedBytes = 0;
for (const path of sources) {
  const source = await readFile(path);
  const [brotliBytes, gzipBytes] = await Promise.all([
    brotli(source, {
      params: {
        [constants.BROTLI_PARAM_QUALITY]: 11,
        [constants.BROTLI_PARAM_MODE]: constants.BROTLI_MODE_TEXT,
      },
    }),
    gzipAsync(source, { level: 9 }),
  ]);
  await Promise.all([
    atomicWrite(`${path}.br`, brotliBytes),
    atomicWrite(`${path}.gz`, gzipBytes),
  ]);
  rawBytes += source.length;
  compressedBytes += brotliBytes.length;
  console.log(`${path}: ${source.length} -> br ${brotliBytes.length}, gzip ${gzipBytes.length}`);
}
let removedSidecars = 0;
for (const path of sidecars) {
  if (!expectedSidecars.has(path)) {
    await unlink(path);
    removedSidecars += 1;
  }
}
console.log(
  `precompressed ${sources.length} assets: ${rawBytes} raw bytes -> ${compressedBytes} Brotli bytes; removed ${removedSidecars} orphaned sidecars`,
);
