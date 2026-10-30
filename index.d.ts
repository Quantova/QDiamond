// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type Shape = 'round' | 'princess' | 'cushion' | 'emerald' | 'oval' | 'radiant' | 'asscher' | 'marquise' | 'pear' | 'heart';
export type Cut = 'poor' | 'fair' | 'good' | 'very_good' | 'excellent' | 'ideal';
export type Clarity = 'fl' | 'if' | 'vvs1' | 'vvs2' | 'vs1' | 'vs2' | 'si1' | 'si2' | 'i1' | 'i2' | 'i3';
export type Lab = 'gia' | 'igi' | 'hrd' | 'ags' | 'gcal';
export type RecordType = 'certify' | 'custody' | 'transfer' | 'redeem';

export interface KeyDescription { format: 'qdiamond-key/1'; algorithm: 'ML-DSA-65'; id: string; publicKey: string; }
export type Party = string | Uint8Array | KeyDescription;
export interface Signer { id: string; publicKey: string; }
export interface Envelope<T = Record<string, unknown>> {
  format: 'qdiamond/1';
  type: RecordType;
  algorithm: 'ML-DSA-65';
  signer: Signer;
  statement: T;
  signature: string;
  anchor?: unknown;
}

export interface CertifyOptions {
  key: Uint8Array;
  shape: Shape;
  caratMc: number;
  cut: Cut;
  colour: string;
  clarity: Clarity;
  lab: Lab;
  reportId: string;
  inscription?: string;
  labLabel?: string;
  certifiedAt?: string;
  note?: string;
}
export interface CustodyOptions { key: Uint8Array; stone: Envelope; vault: string; custodianLabel?: string; custodyAt?: string; note?: string; }
export interface TransferOptions { key: Uint8Array; stone: Envelope; to: Party; toLabel?: string; transferredAt?: string; note?: string; }
export interface RedeemOptions { key: Uint8Array; stone: Envelope; reason: string; redeemedAt?: string; note?: string; }

export interface AnchorOptions {
  seed?: Uint8Array; index?: number; network?: string; rpc?: string; clients?: unknown[];
  trustSingleEndpoint?: boolean; trustCustomEndpoints?: boolean; allowLoopback?: boolean;
  maxFee?: string | number | bigint; meter?: string | number | bigint; timeoutMs?: number;
  onPending?: (pending: unknown) => void; signal?: AbortSignal;
}
export interface VerifyOptions {
  type?: RecordType; prior?: Envelope; stoneId?: string; signerKeyId?: string; signerPublicKey?: string | Uint8Array;
  network: string; strict?: boolean; requireAnchor?: boolean; maxAnchorDelay?: number; at?: string; deadlineMs?: number;
  rpc?: string; clients?: unknown[]; trustSingleEndpoint?: boolean; trustCustomEndpoints?: boolean; allowLoopback?: boolean;
}
export interface Check { name: string; ok: boolean; detail: string; transport: boolean; indeterminate: boolean; unproven: boolean; }
export interface VerifyResult {
  valid: boolean; status: 'valid' | 'unproven' | 'indeterminate' | 'invalid';
  type: RecordType | null; stoneId?: string; signerId?: string; statement?: Record<string, unknown>;
  anchoredAt?: string | null; endpoints: string[]; officialEndpoints: boolean | null; checks: Check[];
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function stoneRef(secret: Uint8Array, reportId: string): string;
export function certify(options: CertifyOptions): Envelope;
export function custody(options: CustodyOptions): Envelope;
export function transfer(options: TransferOptions): Envelope;
export function redeem(options: RedeemOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: AnchorOptions): Promise<Envelope[]>;
export function verify(envelope: Envelope, options: VerifyOptions): Promise<VerifyResult>;
export function anchorDigest(envelope: Envelope): string;
export function recordRef(envelope: Envelope): string;

export const FORMAT: 'qdiamond/1';
export const ALGORITHM: 'ML-DSA-65';
export const KIND: 1302;
export const TYPES: readonly RecordType[];
export const SHAPES: readonly Shape[];
export const CUTS: readonly Cut[];
export const COLOURS: readonly string[];
export const CLARITIES: readonly Clarity[];
export const LABS: readonly Lab[];
export const PUBLIC_KEY_BYTES: 1952;
export const SIGNATURE_BYTES: 3309;
