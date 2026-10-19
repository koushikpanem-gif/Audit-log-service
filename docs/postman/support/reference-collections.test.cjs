const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

function expect(value, message) {
  const chain = {
    eql: expected => assert.deepEqual(value, expected, message),
    include: expected => assert.ok(value.includes(expected), message),
    above: expected => assert.ok(value > expected, message),
    below: expected => assert.ok(value < expected, message),
    least: expected => assert.ok(value >= expected, message),
    match: pattern => assert.match(value, pattern, message),
    a: type => assert.equal(Array.isArray(value) ? 'array' : typeof value, type, message),
  };
  chain.an = chain.a;
  for (const key of ['to', 'be', 'at']) chain[key] = chain;
  chain.not = { match: pattern => assert.doesNotMatch(value, pattern, message) };
  return chain;
}

function requests(items) {
  return items.flatMap(item => item.item ? requests(item.item) : [item]);
}

function harness(initial = {}) {
  const stored = new Map(Object.entries(initial));
  // Hash recomputation is outside these request-state and assertion regressions.
  stored.set('lib', '({checkRecord:()=>[]})');
  const local = new Map();
  const failures = [];
  const pm = {
    collectionVariables: { get: key => stored.get(key), set: (key, value) => stored.set(key, value) },
    variables: {
      get: key => local.has(key) ? local.get(key) : stored.get(key),
      set: (key, value) => local.set(key, value),
      replaceIn: text => text.replace(/\{\{([^}]+)\}\}/g, (_, key) => pm.variables.get(key)),
    },
    expect,
    test: (name, callback) => {
      try { callback(); } catch (error) { failures.push({ name, error }); }
    },
  };
  function run(request, phase, code = 200, body = {}) {
    pm.response = { code, json: () => body, text: () => JSON.stringify(body) };
    const script = request.event.find(event => event.listen === phase).script.exec.join('\n');
    vm.runInNewContext(script, { pm, console: { log() {} } }, { timeout: 1000 });
  }
  return { pm, stored, local, failures, run };
}

for (const filename of [
  'audit-log-service.postman_collection.json',
  'audit-log-verification-suite.postman_collection.json',
]) {
  const collection = JSON.parse(fs.readFileSync(path.join(__dirname, '..', filename), 'utf8'));
  const all = requests(collection.item);
  const find = name => {
    const request = all.find(item => item.name === name);
    assert.ok(request, `Missing request: ${name}`);
    return request;
  };
  const first = find('page 1 (limit=2, asc)');
  const second = find('page 2 via cursor');
  const last = find('page 3 (last) has 1 item and no cursor');
  const limit = all.find(item => item.name.startsWith('export over the small-bundle record limit'));
  assert.ok(limit);

  test(`${filename}: every request script compiles`, () => {
    for (const request of all) {
      for (const event of request.event || []) new vm.Script(event.script.exec.join('\n'));
    }
  });

  test(`${filename}: cursor pages use saved tokens despite higher-priority variables`, () => {
    const h = harness();
    h.run(first, 'test', 200, { items: [{ seq: 1 }, { seq: 2 }], nextCursor: 'page-two' });
    h.local.set('cursor', 'stale-environment-or-data-token');
    h.run(second, 'prerequest');
    assert.equal(h.pm.variables.get('cursor'), 'page-two');
    h.run(second, 'test', 200, { items: [{ seq: 3 }, { seq: 4 }], nextCursor: 'page-three' });
    h.run(last, 'prerequest');
    assert.equal(h.pm.variables.get('cursor'), 'page-three');
    h.run(last, 'test', 200, { items: [{ seq: 5 }], nextCursor: null });
    assert.deepEqual(h.failures, []);
  });

  test(`${filename}: failed page does not replace its cursor with undefined`, () => {
    const h = harness({ cursor: 'valid-token' });
    h.run(second, 'test', 422, { error: { code: 'INVALID_INPUT', message: 'cursor is malformed' } });
    assert.equal(h.stored.get('cursor'), 'valid-token');
    assert.ok(h.failures.length > 0);
    assert.match(h.failures[0].error.message, /cursor is malformed/);
  });

  test(`${filename}: missing cursor reports its prerequisite`, () => {
    for (const value of [undefined, '', 'undefined', 'null']) {
      assert.throws(() => harness({ cursor: value }).run(second, 'prerequest'), /run page 1/);
      assert.throws(() => harness({ cursor: value }).run(last, 'prerequest'), /run page 2/);
    }
  });

  test(`${filename}: export accepts a complete 200 bundle or a specific 422 limit error`, () => {
    for (const [code, body] of [
      [200, { format: 'audit-export-bundle/v1', records: Array(8).fill({}), recordCount: 8 }],
      [422, { error: { code: 'EXPORT_LIMIT_EXCEEDED', message: 'Selection exceeds limit', details: [] } }],
    ]) {
      const h = harness();
      h.run(limit, 'test', code, body);
      assert.deepEqual(h.failures, []);
    }
    for (const [code, body] of [
      [200, { format: 'audit-export-bundle/v1', records: [], recordCount: 8 }],
      [422, { error: { code: 'INVALID_INPUT', message: 'Invalid selection', details: [] } }],
      [500, { error: { code: 'INTERNAL_ERROR' } }],
    ]) {
      const h = harness();
      h.run(limit, 'test', code, body);
      assert.ok(h.failures.length > 0);
    }
  });

  test(`${filename}: export fixture waits for and checks all eight appends`, async () => {
    const h = harness({ baseUrl: 'http://fixture', runId: 'test', writerKey: 'test-writer' });
    const sent = [];
    let active = 0;
    const pending = [];
    h.pm.sendRequest = (request, callback) => {
      assert.equal(active, 0, 'Fixture appends must be sequential');
      active++;
      sent.push(JSON.parse(request.body.raw).payload.i);
      pending.push(new Promise(resolve => setImmediate(() => {
        active--;
        callback(null, { code: 201 });
        resolve();
      })));
    };
    h.run(limit, 'prerequest');
    for (let index = 0; index < 8; index++) await pending[index];
    assert.deepEqual(sent, [0, 1, 2, 3, 4, 5, 6, 7]);
    assert.deepEqual(h.failures, []);
  });
}
