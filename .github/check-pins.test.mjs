import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync, readdirSync } from 'node:fs';
import { checkPins } from './check-pins.mjs';

const revision = '6b94dacd7fa04aa8847c62c6471a1fc5c0f6c9dc';
const older = '9c076b1e4050529406df27533e12c8e0dd1fc0db';
const source = (name, rev = revision) =>
  `git+https://github.com/corbet-foss/${name}?rev=${rev}#${rev}`;
const pkg = (name, source = null, dependencies = []) => ({ name, source, dependencies });
const graph = (...packages) => ({
  packages: [pkg('crbk'), pkg('crlt', source('crlt')), ...packages],
});

test('accept a single revision per leaf and unrelated registry duplicates', () => {
  checkPins(graph(pkg('serde'), pkg('thiserror'), pkg('thiserror')));
});

test('reject duplicate direct and transitive Corbet packages', () => {
  assert.throws(() => checkPins(graph(pkg('crlt', source('crlt', older)))), /duplicated/);
  assert.throws(() => checkPins(graph(
    pkg('csgn', source('csgn')), pkg('csgn', source('csgn', older)),
  )), /duplicated/);
  assert.throws(() => checkPins(graph(pkg('crlt'))), /duplicated/);
});

test('reject branch, tag, unqualified and abbreviated pins', () => {
  for (const query of ['branch=main', 'tag=v1', '', `rev=${revision.slice(0, 7)}`]) {
    const floating = `git+https://github.com/corbet-foss/csgn?${query}#${revision}`;
    assert.throws(() => checkPins(graph(pkg('csgn', floating))), /revision pin/);
  }
});

test('reject a resolved revision different from its pin', () => {
  const mismatch = source('csgn').replace(`#${revision}`, `#${older}`);
  assert.throws(() => checkPins(graph(pkg('csgn', mismatch))), /revision pin/);
});

test('reject floating transitive declarations even with a pinned resolution', () => {
  const dependency = { source: 'git+https://github.com/corbet-foss/cpns?branch=main' };
  assert.throws(() => checkPins(graph(
    pkg('cgrd', source('cgrd'), [dependency]), pkg('cpns', source('cpns')),
  )), /revision pin/);
});

test('require the crlt Git dependency', () => {
  assert.throws(() => checkPins({ packages: [pkg('crbk')] }), /Missing/);
  assert.throws(() => checkPins({ packages: [pkg('crbk'), pkg('crlt')] }), /unpinned/);
});

test('pin every CI action while selecting current stable Rust', () => {
  const directory = new URL('./workflows/', import.meta.url);
  const files = readdirSync(directory).filter(name => /\.ya?ml$/.test(name));
  assert.ok(files.length > 0);
  for (const file of files) {
    const workflow = readFileSync(new URL(file, directory), 'utf8');
    const actions = [...workflow.matchAll(/uses:\s*([\w./-]+)@(\S+)/g)];
    assert.ok(actions.length > 0);
    for (const [, name, revision] of actions) {
      assert.match(revision, /^[a-f0-9]{40}$/, `${file}: ${name} must be immutable`);
    }
    assert.match(workflow, /toolchain: stable/);
  }
});
