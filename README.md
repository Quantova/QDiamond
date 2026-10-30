# QDiamond

QDiamond is a live production post quantum provenance and chain of custody tool for diamonds on the Quantova network. It proves the laboratory certification, vault custody, transfer and redemption of graded diamonds, and it lets any third party confirm that history without trusting the party that created it.

QDiamond proves records without disclosing them. Stone identities and holder details stay private on the systems of the party that holds them. Only a salted cryptographic commitment is written to the chain, and no commercial detail is ever published.

## What it records

Each record is a signed envelope of one of four types.

1. certify, a grading laboratory states the shape, the weight in milli carats, the cut, the colour, the clarity, the laboratory, the report number and the inscription of a graded stone.
2. custody, a custodian states that a stone is held in a named vault.
3. transfer, the holder of a stone moves it to another party.
4. redeem, the holder removes a stone from the chain of custody and states why.

Every record is signed with ML-DSA-65 under FIPS 204 by the party whose role it names, and each later record links to the one before it so the whole life of a stone forms a chain.

## Proving the time

A record on its own carries only the claim of its signer. Anchoring a record on the Quantova network through Qstamp adds a post quantum evidence anchor that fixes the latest moment the record existed, provable against the record and the signer by anyone, without claiming a regulated timestamp status that Quantova Inc does not hold.

## Install

```
npm install @quantovainc/qdiamond
```

## Use

```js
const qdiamond = require('@quantovainc/qdiamond');

const lab = qdiamond.generateKey();
const stone = qdiamond.certify({
  key: lab,
  shape: 'round',
  caratMc: 1010,
  cut: 'excellent',
  colour: 'f',
  clarity: 'vvs1',
  lab: 'gia',
  reportId: 'GIA 2201234567',
  inscription: 'GIA 2201234567',
  labLabel: 'GIA',
});

const anchored = await qdiamond.anchor(stone, { seed, index: 0, network: 'testnet' });
const result = await qdiamond.verify(anchored[0], { type: 'certify', network: 'testnet' });
```

## What a record does not establish

1. It does not show that the stated grading is true. It shows only that the signer stated it and that the statement existed unchanged at a point in time.
2. It does not identify a natural or legal person. The signer is a chain address, and linking an address to a laboratory, custodian or holder is a separate attestation.
3. The labels are text written by the signer, they are not a verified identity.

## License

Apache-2.0 OR MIT
