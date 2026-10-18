#!/usr/bin/env node
/**
 * Build gate: every module must parse, and the CLI must load. No transpiler, no bundler —
 * the shipped artefact is the source.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const roots = ['src', 'test', 'scripts'];
const files = [];
for (const root of roots) {
  if (!fs.existsSync(root)) continue;
  for (const name of fs.readdirSync(root)) {
    if (name.endsWith('.js')) files.push(path.join(root, name));
  }
}
files.push('src/cli.js');

const unique = [...new Set(files)];
let failed = 0;

for (const file of unique) {
  const res = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (res.status !== 0) {
    failed += 1;
    process.stderr.write(`\n✗ ${file}\n${res.stderr || res.stdout}\n`);
  }
}

if (failed > 0) {
  process.stderr.write(`\nbuild failed: ${failed}/${unique.length} files did not parse\n`);
  process.exit(1);
}

// The CLI must also resolve its import graph.
const loaded = spawnSync(process.execPath, ['src/cli.js'], { encoding: 'utf8' });
if (loaded.status !== 2) {
  process.stderr.write(`\n✗ src/cli.js did not load cleanly\n${loaded.stderr || loaded.stdout}\n`);
  process.exit(1);
}

process.stdout.write(`build ok — ${unique.length} modules parsed, cli loaded\n`);
