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
const { brotliDecompressSync, gunzipSync } = require('node:zlib');

const execFileAsync = promisify(execFile);
const precompressScript = path.resolve(
  __dirname,
  '../scripts/precompress_static.mjs',
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
    env: { ...process.env, NUMOJ_STATIC_ROOT: 'static' },
  });

  const gzipBytes = await readFile(`${sourcePath}.gz`);
  assert.deepEqual(gzipBytes.subarray(0, 3), Buffer.from([0x1f, 0x8b, 0x08]));
  assert.equal(gzipBytes[9], 0xff);
  assert.deepEqual(gunzipSync(gzipBytes), source);
});

test('precompress removes only orphaned sidecars tracked by its manifest', async (t) => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'numoj-precompress-'));
  t.after(() => rm(workspace, { recursive: true, force: true }));

  const staticRoot = path.join(workspace, 'static');
  const manifestPath = path.join(workspace, 'state', 'manifest.json');
  const expectedSourcePath = path.join(staticRoot, 'expected.js');
  const expectedSource = Buffer.from('const expected = true;\n'.repeat(6_000));
  const expectedBrotliPath = `${expectedSourcePath}.br`;
  const expectedGzipPath = `${expectedSourcePath}.gz`;
  await mkdir(staticRoot);
  await writeFile(expectedSourcePath, expectedSource);
  await writeFile(expectedBrotliPath, 'stale-brotli');
  await writeFile(expectedGzipPath, 'stale-gzip');

  const smallSourcePath = path.join(staticRoot, 'small.js');
  await writeFile(smallSourcePath, 'small');
  const unmanagedPaths = [
    `${smallSourcePath}.br`,
    `${smallSourcePath}.gz`,
    path.join(staticRoot, 'missing.js.br'),
    path.join(staticRoot, 'missing.js.gz'),
    path.join(staticRoot, 'large.bin.br'),
    path.join(staticRoot, 'large.bin.gz'),
  ];
  await Promise.all(unmanagedPaths.map((filePath) => writeFile(filePath, 'orphaned')));
  await writeFile(path.join(staticRoot, 'large.bin'), Buffer.alloc(100 * 1024, 'x'));

  const runPrecompress = () => execFileAsync(process.execPath, [precompressScript], {
    cwd: workspace,
    env: {
      ...process.env,
      NUMOJ_STATIC_ROOT: staticRoot,
      NUMOJ_PRECOMPRESS_MANIFEST: manifestPath,
    },
  });

  await runPrecompress();

  assert.deepEqual(
    brotliDecompressSync(await readFile(expectedBrotliPath)),
    expectedSource,
  );
  assert.deepEqual(gunzipSync(await readFile(expectedGzipPath)), expectedSource);
  await Promise.all(unmanagedPaths.map((filePath) => readFile(filePath)));

  await writeFile(expectedSourcePath, 'small now');
  await runPrecompress();

  await assert.rejects(readFile(expectedBrotliPath), { code: 'ENOENT' });
  await assert.rejects(readFile(expectedGzipPath), { code: 'ENOENT' });
  await Promise.all(unmanagedPaths.map((filePath) => readFile(filePath)));
});
