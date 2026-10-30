// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

const OPTS = { network: 'testnet', requireAnchor: false, strict: false };
function stone() {
  const key = Q.generateKey();
  return { key, env: Q.certify({ key, shape: 'round', caratMc: 1010, cut: 'excellent', colour: 'f', clarity: 'vvs1', lab: 'gia', reportId: 'GIA 2201234567' }) };
}

test('replay as another record type is refused', async () => {
  const { env } = stone();
  const forged = JSON.parse(JSON.stringify(env)); forged.type = 'custody';
  const r = await Q.verify(forged, Object.assign({ type: 'custody' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
});

test('replay onto another stone id is refused', async () => {
  const { env } = stone();
  const forged = JSON.parse(JSON.stringify(env)); forged.statement.stoneId = 'f'.repeat(32);
  const r = await Q.verify(forged, Object.assign({ type: 'certify' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
});

test('every signed field is bound, a change to any of them breaks the signature', async () => {
  const { env } = stone();
  const muts = [
    (s) => { s.shape = 'oval'; }, (s) => { s.caratMc += 1; }, (s) => { s.cut = 'good'; },
    (s) => { s.colour = 'g'; }, (s) => { s.clarity = 'if'; }, (s) => { s.lab = 'igi'; },
    (s) => { s.reportId = 'GIA 9'; }, (s) => { s.inscription = 'x'; }, (s) => { s.certifiedAt = '2000-01-01T00:00:00.000Z'; },
  ];
  for (const m of muts) {
    const forged = JSON.parse(JSON.stringify(env)); m(forged.statement);
    const r = await Q.verify(forged, Object.assign({ type: 'certify' }, OPTS));
    assert.strictEqual(r.status, 'invalid', JSON.stringify(forged.statement));
  }
});

test('a signature from another key, non canonical base64, extra field or prototype pollution is refused', async () => {
  const a = stone(); const b = stone();
  const wrongSigner = JSON.parse(JSON.stringify(a.env)); wrongSigner.signer = b.env.signer;
  assert.strictEqual((await Q.verify(wrongSigner, Object.assign({ type: 'certify' }, OPTS))).status, 'invalid');
  const badB64 = JSON.parse(JSON.stringify(a.env)); badB64.signature = badB64.signature.slice(0, -4) + 'AAAA';
  assert.strictEqual((await Q.verify(badB64, Object.assign({ type: 'certify' }, OPTS))).status, 'invalid');
  const extra = JSON.parse(JSON.stringify(a.env)); extra.statement.extra = 1;
  assert.strictEqual((await Q.verify(extra, Object.assign({ type: 'certify' }, OPTS))).status, 'invalid');
  const pollute = JSON.parse(JSON.stringify(a.env));
  pollute.statement = JSON.parse('{"__proto__":{"polluted":true},"stoneId":"' + a.env.statement.stoneId + '"}');
  assert.strictEqual((await Q.verify(pollute, Object.assign({ type: 'certify' }, OPTS))).status, 'invalid');
  assert.strictEqual({}.polluted, undefined);
});

test('a signing key is never serialised and a wrong anchor kind is not accepted', async () => {
  const k = Q.generateKey();
  assert.strictEqual(JSON.stringify({ k }), '{"k":"SecretKey [hidden]"}');
  const { env } = stone();
  const anchored = JSON.parse(JSON.stringify(env));
  anchored.anchor = { kind: '1301', chain: { id: 'x', genesis: 'y' }, anchor: { time: 1, height: 1, tx: 't' }, proof: { index: 0 } };
  const r = await Q.verify(anchored, { type: 'certify', network: 'testnet', requireAnchor: true, strict: false });
  assert.strictEqual(r.status, 'invalid');
});
