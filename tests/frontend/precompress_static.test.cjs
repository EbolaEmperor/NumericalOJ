'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { gunzipSync } = require('node:zlib');

const execFileAsync = promisify(execFile);
const precompressScript = path.resolve(
  __dirname,
  '../../scripts/precompress_static.mjs',
);

test('precompressed gzip sidecars use a platform-neutral header', async (t) => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'numoj-precompress-'));
  t.after(() => rm(workspace, { recursive: true, force: true }));

  const staticRoot = path.join(workspace, 'static');
  const sourcePath = path.join(staticRoot, 'portable.js');
  const source = Buffer.from(
    'const portableCompressionFixture = "NumericalOJ";\n'.repeat(4096),
  );
  await mkdir(staticRoot);
  await writeFile(sourcePath, source);

  await execFileAsync(process.execPath, [precompressScript], {
    cwd: workspace,
  });

  const gzipBytes = await readFile(`${sourcePath}.gz`);
  assert.deepEqual(gzipBytes.subarray(0, 3), Buffer.from([0x1f, 0x8b, 0x08]));
  assert.equal(gzipBytes[9], 0xff);
  assert.deepEqual(gunzipSync(gzipBytes), source);
});
