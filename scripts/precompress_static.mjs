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
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...await collect(path));
    } else if (
      entry.isFile()
      && compressibleExtensions.has(extname(entry.name))
      && !entry.name.endsWith(".br")
      && !entry.name.endsWith(".gz")
      && (await stat(path)).size >= minimumBytes
    ) {
      files.push(path);
    }
  }
  return files;
}

async function atomicWrite(path, bytes) {
  const temporary = `${path}.tmp-${process.pid}`;
  await writeFile(temporary, bytes, { mode: 0o644 });
  await rename(temporary, path);
}

const files = await collect(staticRoot);
let rawBytes = 0;
let compressedBytes = 0;
for (const path of files) {
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
console.log(
  `precompressed ${files.length} assets: ${rawBytes} raw bytes -> ${compressedBytes} Brotli bytes`,
);
