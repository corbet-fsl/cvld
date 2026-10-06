import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBrowser, checkPins } from './check-pins.mjs';

const revision = '6b94dacd7fa04aa8847c62c6471a1fc5c0f6c9dc';
const older = '9c076b1e4050529406df27533e12c8e0dd1fc0db';
const source = (name, rev = revision) =>
  `git+https://github.com/corbet-foss/${name}?branch=main#${rev}`;
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

test('reject other branches, tags, unqualified and abbreviated revisions', () => {
  for (const query of ['branch=develop', 'tag=v1', '', `rev=${revision.slice(0, 7)}`]) {
    const floating = `git+https://github.com/corbet-foss/csgn?${query}#${revision}`;
    assert.throws(() => checkPins(graph(pkg('csgn', floating))), /Expected main/);
  }
});

test('reject every matching transitive revision pin', () => {
  const pinned = `git+https://github.com/corbet-foss/csgn?rev=${revision}#${revision}`;
  assert.throws(() => checkPins(graph(pkg('csgn', pinned))), /Expected main/);
  assert.throws(() => checkPins(graph(pkg('csgn', source('csgn'), [
    { source: pinned.split('#')[0] },
  ]))), /Expected main/);
});

test('accept main declarations with a unique complete resolution', () => {
  const dependency = { source: 'git+https://github.com/corbet-foss/cpns?branch=main' };
  checkPins(graph(
    pkg('cgrd', source('cgrd'), [dependency]),
    pkg('cpns', `git+https://github.com/corbet-foss/cpns?branch=main#${revision}`),
  ));
});

test('require the crlt Git dependency', () => {
  assert.throws(() => checkPins({ packages: [pkg('crbk')] }), /Missing/);
  assert.throws(() => checkPins({ packages: [pkg('crbk'), pkg('crlt')] }), /invalid/);
});

const browserGraph = () => ({
  packages: [{ ...pkg('cvld'), id: 'owner', manifest_path: '/repo/Cargo.toml' }],
  resolve: { nodes: [{ id: 'owner', features: ['client', 'client-browser'] }] },
});

test('browser consumer measures the exact local owner without the server graph', () => {
  checkBrowser(browserGraph(), '/repo');
  const data = browserGraph();
  data.packages[0].manifest_path = '/different/Cargo.toml';
  assert.throws(() => checkBrowser(data, '/repo'), /exact local/);
  data.packages[0].manifest_path = '/repo/Cargo.toml';
  data.packages[0].source = source('cvld');
  assert.throws(() => checkBrowser(data, '/repo'), /exact local/);
});

test('browser graph cannot substitute a native-only or server consumer', () => {
  const data = browserGraph();
  data.resolve.nodes[0].features = ['client'];
  assert.throws(() => checkBrowser(data, '/repo'), /portable owner/);
  for (const feature of ['server', 'client-http', 'development-gate']) {
    data.resolve.nodes[0].features = ['client-browser', feature];
    assert.throws(() => checkBrowser(data, '/repo'), /portable owner/);
  }
});

test('independent browser graph still rejects pinned first-party sources', () => {
  const data = browserGraph();
  data.packages.push(pkg('example', source('example').replace('branch=main', `rev=${revision}`)));
  assert.throws(() => checkBrowser(data, '/repo'), /Expected main/);
});
