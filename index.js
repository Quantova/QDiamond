// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const D = require('./lib/diamond');
const { verify } = require('./lib/verify');
const F = require('./lib/format');

module.exports = {
  generateKey: D.generateKey,
  publicKey: D.publicKey,
  keyId: D.keyId,
  describeKey: D.describeKey,
  stoneRef: D.stoneRef,
  certify: D.certify,
  custody: D.custody,
  transfer: D.transfer,
  redeem: D.redeem,
  anchor: D.anchor,
  complete: D.complete,
  verify,
  anchorDigest: (envelope) => F.anchorDigest(F.parse(envelope)).toString('hex'),
  recordRef: (envelope) => F.refOf(F.parse(envelope)),
  FORMAT: F.FORMAT,
  ALGORITHM: F.ALGORITHM,
  KIND: F.KIND,
  TYPES: F.TYPES,
  SHAPES: F.SHAPES,
  CUTS: F.CUTS,
  COLOURS: F.COLOURS,
  CLARITIES: F.CLARITIES,
  LABS: F.LABS,
  PUBLIC_KEY_BYTES: F.PUBLIC_KEY_BYTES,
  SIGNATURE_BYTES: F.SIGNATURE_BYTES,
};
