import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkPins } from './check-pins.mjs';

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


test('canonical sources reject pins and mixed-origin duplicates', () => {
  const canonical = source('crlt').replace('github.com', 'git.corbet.ch');
  checkPins({ packages: [pkg('crlt', canonical)] });
  assert.throws(() => checkPins(graph(pkg('crlt', canonical))), /duplicated/);
  assert.throws(() => checkPins({ packages: [pkg('crlt', canonical.replace('branch=main', `rev=${revision}`))] }), /Expected main/);
});

test('accept exact original issuer resolutions and transitive declarations', () => {
  const issuers = ['cmbl', 'cmmr'].map(name => ({
    ...pkg(name, `git+https://git.corbet.ch/corbet-foss/${name}.git?branch=v01#${revision}`),
    version: '0.1.0',
  }));
  const dependencies = issuers.map(owner => ({
    name: owner.name, source: owner.source.split('#')[0],
  }));
  checkPins(graph(pkg('cblc', source('cblc'), dependencies), ...issuers));
});

test('reject original owner substitutions, aliases, versions and duplicate identities', () => {
  for (const name of ['cmbl', 'cmmr']) {
    const original = `git+https://git.corbet.ch/corbet-foss/${name}.git?branch=v01#${revision}`;
    const owner = { ...pkg(name, original), version: '0.1.0' };
    for (const bad of [
      { ...owner, name: 'other' },
      { ...owner, name: name === 'cmbl' ? 'cmmr' : 'cmbl' },
      { ...owner, version: '0.2.0' },
      { ...owner, version: undefined },
      { ...owner, source: null },
      { ...owner, source: 'registry+https://example.test/index' },
      ...[
        original.replace('git.corbet.ch', 'github.com'),
        original.replace('corbet-foss', 'corbet-libs'),
        original.replace('git.corbet.ch', 'git.corbet.ch.evil.test'),
        original.replace('git.corbet.ch', 'user@git.corbet.ch'),
        original.replace('git.corbet.ch', 'git.corbet.ch:443'),
        original.replace('.git?', '?'),
        original.replace('git+', ''),
        original.replace('v01', 'v02'),
        original.replace('v01', 'v%30%31'),
        original.replace('branch=v01', 'tag=v01'),
        original.replace('branch=v01', `rev=${revision}`),
        original.replace('branch=v01', 'branch=v01&branch=v01'),
        original.replace('branch=v01', 'branch=v01&extra='),
        original.replace(`#${revision}`, '#short'),
        original.replace(`#${revision}`, `#${revision.toUpperCase()}`),
      ].map(badSource => ({ ...owner, source: badSource })),
    ]) assert.throws(() => checkPins(graph(bad)));
    assert.throws(() => checkPins(graph(owner, owner)), /duplicated/);
    assert.throws(() => checkPins(graph(owner, pkg(name))), /duplicated/);
    checkPins(graph({ ...owner, source: original.replace('branch=v01', 'branch=main') }));
  }
});

test('reject altered and unresolved original transitive selectors', () => {
  const name = 'cmbl';
  const declaration = `git+https://git.corbet.ch/corbet-foss/${name}.git?branch=v01`;
  const owner = { ...pkg(name, `${declaration}#${revision}`), version: '0.1.0' };
  for (const raw of [
    declaration.replace('v01', 'v02'),
    declaration.replace('v01', 'v%30%31'),
    `${declaration}&branch=v01`,
    `${declaration}#${revision}`,
    declaration.replace('.git?', '?'),
    declaration.replace('git.corbet.ch', 'github.com'),
    'registry+https://example.test/index',
    null,
  ]) assert.throws(() => checkPins(graph(
    owner, pkg('cblc', source('cblc'), [{ name, source: raw }]),
  )));
  assert.throws(() => checkPins(graph(
    pkg('cblc', source('cblc'), [{ name, source: declaration }]),
  )));
  assert.throws(() => checkPins(graph(
    owner, pkg('cblc', source('cblc'), [{ name: 'other', source: declaration }]),
  )), /Expected main/);
});
