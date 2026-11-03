'use strict';

const { after, before, test } = require('node:test');
const assert = require('node:assert/strict');

const app = require('../src/app');

let server;
let baseUrl;

before(async () => {
  server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

test('GET /health returns 200 and {"status":"ok"}', async () => {
  const res = await fetch(`${baseUrl}/health`);

  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /^application\/json/);
  assert.deepEqual(await res.json(), { status: 'ok' });
});

test('GET /health returns exactly the status field', async () => {
  const res = await fetch(`${baseUrl}/health`);
  const body = await res.json();

  assert.deepEqual(Object.keys(body), ['status']);
});

test('GET /unknown returns 404', async () => {
  const res = await fetch(`${baseUrl}/unknown`);

  assert.equal(res.status, 404);
});
