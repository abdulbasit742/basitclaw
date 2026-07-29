import { randomUUID } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync
} from 'node:fs';
import { dirname, resolve } from 'node:path';

export function createSecurityArchiveFilesystem(directory) {
  const root = resolve(String(directory));
  const segmentsDirectory = resolve(root, 'segments');
  const headPath = resolve(root, 'head.json');
  const anchorPath = resolve(root, 'anchor.json');
  const prunePlanPath = resolve(root, 'prune-plan.json');
  mkdirSync(segmentsDirectory, { recursive: true, mode: 0o700 });

  function segmentNames() {
    return readdirSync(segmentsDirectory)
      .filter((name) => /^segment-\d{4}-\d{2}-\d{2}-\d{6}\.ndjson$/.test(name))
      .sort();
  }

  function readSegment(name) {
    const content = readFileSync(resolve(segmentsDirectory, name), 'utf8').trim();
    if (!content) return [];
    return content.split('\n').map((line) => JSON.parse(line));
  }

  function readAll() {
    const output = [];
    for (const segment of segmentNames()) {
      for (const envelope of readSegment(segment)) output.push({ envelope, segment });
    }
    output.sort((left, right) => left.envelope.sequence - right.envelope.sequence);
    return output;
  }

  function appendSegment(name, line) {
    const path = resolve(segmentsDirectory, name);
    const existing = existsSync(path) ? readFileSync(path) : Buffer.alloc(0);
    atomicWrite(path, Buffer.concat([existing, Buffer.from(line, 'utf8')]));
  }

  function selectSegment(current, currentSegment, maxBytes) {
    const date = current.toISOString().slice(0, 10);
    if (currentSegment?.startsWith(`segment-${date}-`)) {
      const path = resolve(segmentsDirectory, currentSegment);
      if (!existsSync(path) || statSync(path).size < maxBytes) return currentSegment;
    }
    const ordinals = segmentNames()
      .filter((name) => name.startsWith(`segment-${date}-`))
      .map((name) => Number(name.match(/-(\d{6})\.ndjson$/)?.[1] ?? 0));
    return `segment-${date}-${String((ordinals.length ? Math.max(...ordinals) : 0) + 1).padStart(6, '0')}.ndjson`;
  }

  function readJson(path, fallback = null) {
    if (!existsSync(path)) return fallback;
    return JSON.parse(readFileSync(path, 'utf8'));
  }

  function writeJson(path, value) {
    atomicWrite(path, Buffer.from(`${JSON.stringify(value)}\n`, 'utf8'));
  }

  function atomicWrite(path, content) {
    const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
    const descriptor = openSync(temporary, 'wx', 0o600);
    try {
      writeFileSync(descriptor, content);
      fsyncSync(descriptor);
    } finally { closeSync(descriptor); }
    renameSync(temporary, path);
    fsyncDirectory(dirname(path));
  }

  function fsyncDirectory(directoryPath) {
    const descriptor = openSync(directoryPath, 'r');
    try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
  }

  return {
    root,
    segmentsDirectory,
    headPath,
    anchorPath,
    prunePlanPath,
    segmentNames,
    readSegment,
    readAll,
    appendSegment,
    selectSegment,
    readJson,
    writeJson,
    exists: existsSync,
    rename: renameSync,
    remove: (path) => rmSync(path, { force: true }),
    resolveSegment: (name) => resolve(segmentsDirectory, name),
    sync: () => { fsyncDirectory(root); fsyncDirectory(segmentsDirectory); }
  };
}
