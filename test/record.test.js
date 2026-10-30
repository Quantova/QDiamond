// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

const key = () => Q.generateKey();
function certifyStone(lab) {
  return Q.certify({ key: lab, shape: 'round', caratMc: 1010, cut: 'excellent', colour: 'f', clarity: 'vvs1', lab: 'gia', reportId: 'GIA 2201234567', inscription: 'GIA 2201234567', labLabel: 'GIA' });
}

test('a certified stone is a well formed signed record of the lab', () => {
  const lab = key();
  const s = certifyStone(lab);
  assert.strictEqual(s.format, 'qdiamond/1');
  assert.strictEqual(s.type, 'certify');
  assert.strictEqual(s.signer.id, Q.keyId(lab));
  assert.strictEqual(s.statement.labKeyId, Q.keyId(lab));
  assert.match(s.statement.stoneId, /^[0-9a-f]{32}$/);
  assert.strictEqual(Buffer.from(s.signer.publicKey, 'base64').length, Q.PUBLIC_KEY_BYTES);
  assert.strictEqual(Buffer.from(s.signature, 'base64').length, Q.SIGNATURE_BYTES);
});

test('custody and transfer chain to the same stone', () => {
  const lab = key(); const custodian = key(); const buyer = key();
  const s = certifyStone(lab);
  const held = Q.custody({ key: custodian, stone: s, vault: 'Antwerp Vault 3' });
  const moved = Q.transfer({ key: custodian, stone: held, to: Q.keyId(buyer), toLabel: 'Acme Gems Ltd' });
  assert.strictEqual(held.statement.stoneId, s.statement.stoneId);
  assert.strictEqual(held.statement.stoneRef, Q.recordRef(s));
  assert.strictEqual(moved.statement.fromKeyId, Q.keyId(custodian));
  assert.strictEqual(moved.statement.toKeyId, Q.keyId(buyer));
  assert.strictEqual(moved.statement.stoneRef, Q.recordRef(held));
});

test('invalid inputs are refused before anything is signed', () => {
  const k = key();
  const base = { key: k, shape: 'round', caratMc: 1010, cut: 'excellent', colour: 'f', clarity: 'vvs1', lab: 'gia', reportId: 'GIA 1' };
  assert.throws(() => Q.certify(Object.assign({}, base, { shape: 'star' })), /shape must be one of/);
  assert.throws(() => Q.certify(Object.assign({}, base, { cut: 'amazing' })), /cut must be one of/);
  assert.throws(() => Q.certify(Object.assign({}, base, { colour: 'c' })), /colour must be one of/);
  assert.throws(() => Q.certify(Object.assign({}, base, { clarity: 'perfect' })), /clarity must be one of/);
  assert.throws(() => Q.certify(Object.assign({}, base, { lab: 'acme' })), /lab must be one of/);
  assert.throws(() => Q.certify(Object.assign({}, base, { caratMc: 5000000 })), /caratMc is larger than/);
  assert.throws(() => Q.certify(Object.assign({}, base, { caratMc: 1.5 })), /caratMc must be a whole number/);
  assert.throws(() => Q.certify(Object.assign({}, base, { reportId: '' })), /reportId is 1 to/);
  assert.throws(() => Q.certify(Object.assign({}, base, { nope: 1 })), /is not an option of certify/);
});

test('a transfer refuses a recipient equal to the sender', () => {
  const holder = key();
  const s = certifyStone(holder);
  assert.throws(() => Q.transfer({ key: holder, stone: s, to: Q.keyId(holder) }), /the receiving key must differ/);
});

test('a well formed record verifies and a type mismatch or tamper is invalid', async () => {
  const lab = key();
  const s = certifyStone(lab);
  const ok = await Q.verify(s, { type: 'certify', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.stoneId, s.statement.stoneId);
  const wrongType = await Q.verify(s, { type: 'custody', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(wrongType.status, 'invalid');
  const forged = JSON.parse(JSON.stringify(s));
  forged.statement.clarity = 'if';
  const tampered = await Q.verify(forged, { type: 'certify', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(tampered.status, 'invalid');
});

test('the prior link binds a record to the record before it', async () => {
  const lab = key(); const custodian = key();
  const s = certifyStone(lab);
  const held = Q.custody({ key: custodian, stone: s, vault: 'Antwerp Vault 3' });
  const good = await Q.verify(held, { type: 'custody', network: 'testnet', requireAnchor: false, strict: false, prior: s });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  const other = certifyStone(lab);
  const bad = await Q.verify(held, { type: 'custody', network: 'testnet', requireAnchor: false, strict: false, prior: other });
  assert.strictEqual(bad.status, 'invalid');
});

test('stoneRef is deterministic and the kind and constants are the pinned ones', () => {
  const secret = new Uint8Array(32); globalThis.crypto.getRandomValues(secret);
  assert.strictEqual(Q.stoneRef(secret, 'GIA 1'), Q.stoneRef(secret, 'GIA 1'));
  assert.notStrictEqual(Q.stoneRef(secret, 'GIA 1'), Q.stoneRef(secret, 'GIA 2'));
  assert.strictEqual(Q.KIND, 1302);
  assert.strictEqual(Q.FORMAT, 'qdiamond/1');
  assert.deepStrictEqual([...Q.TYPES], ['certify', 'custody', 'transfer', 'redeem']);
});
