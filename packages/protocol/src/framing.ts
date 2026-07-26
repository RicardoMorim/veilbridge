/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

import { Buffer } from "node:buffer";

import { ProtocolError } from "./errors.js";

export const PROTOCOL_VERSION = 1 as const;
export const WIRE_PREFIX = "vb1.";
export const IDENTIFIER_BYTES = 16;
export const NONCE_BYTES = 12;
export const MAX_CIPHERTEXT_BYTES = 48 * 1024;

const MAGIC = Uint8Array.of(0x56, 0x42);
const AUTHENTICATED_HEADER_BYTES = 47;
const FIXED_HEADER_BYTES = 63;
const CIPHERTEXT_LENGTH_OFFSET = 59;
const MAX_UINT64 = (1n << 64n) - 1n;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;

export enum MessageType {
  Direct = 1,
}

export enum CipherSuite {
  Aes256GcmContentKey = 1,
}

export interface MessageMetadata {
  conversationId: Uint8Array;
  senderDeviceId: Uint8Array;
  sequence: bigint;
}

export interface Envelope extends MessageMetadata {
  version: typeof PROTOCOL_VERSION;
  messageType: MessageType;
  cipherSuite: CipherSuite;
  flags: number;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export type AuthenticatedHeader = Pick<
  Envelope,
  | "version"
  | "messageType"
  | "cipherSuite"
  | "flags"
  | "conversationId"
  | "senderDeviceId"
  | "sequence"
>;

function assertByteArray(
  value: unknown,
  length: number,
  code: "invalid_identifier" | "invalid_nonce",
  label: string,
): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength !== length) {
    throw new ProtocolError(code, `${label} must be exactly ${length} bytes`);
  }
}

function validateAuthenticatedHeader(header: AuthenticatedHeader): void {
  if (header.version !== PROTOCOL_VERSION) {
    throw new ProtocolError(
      "unsupported_version",
      `Unsupported envelope version: ${String(header.version)}`,
    );
  }
  if (header.messageType !== MessageType.Direct) {
    throw new ProtocolError(
      "unsupported_message_type",
      `Unsupported message type: ${String(header.messageType)}`,
    );
  }
  if (header.cipherSuite !== CipherSuite.Aes256GcmContentKey) {
    throw new ProtocolError(
      "unsupported_cipher_suite",
      `Unsupported cipher suite: ${String(header.cipherSuite)}`,
    );
  }
  if (!Number.isInteger(header.flags) || header.flags !== 0) {
    throw new ProtocolError(
      "unsupported_flags",
      `Unsupported critical flags: ${String(header.flags)}`,
    );
  }

  assertByteArray(
    header.conversationId,
    IDENTIFIER_BYTES,
    "invalid_identifier",
    "conversationId",
  );
  assertByteArray(
    header.senderDeviceId,
    IDENTIFIER_BYTES,
    "invalid_identifier",
    "senderDeviceId",
  );

  if (
    typeof header.sequence !== "bigint" ||
    header.sequence < 0n ||
    header.sequence > MAX_UINT64
  ) {
    throw new ProtocolError(
      "invalid_sequence",
      "sequence must be an unsigned 64-bit integer",
    );
  }
}

export function encodeAuthenticatedHeader(
  header: AuthenticatedHeader,
): Uint8Array {
  validateAuthenticatedHeader(header);

  const bytes = Buffer.alloc(AUTHENTICATED_HEADER_BYTES);
  bytes.set(MAGIC, 0);
  bytes[2] = header.version;
  bytes[3] = header.messageType;
  bytes.writeUInt16BE(header.cipherSuite, 4);
  bytes[6] = header.flags;
  bytes.set(header.conversationId, 7);
  bytes.set(header.senderDeviceId, 23);
  bytes.writeBigUInt64BE(header.sequence, 39);

  return Uint8Array.from(bytes);
}

export function encodeEnvelope(envelope: Envelope): string {
  const authenticatedHeader = encodeAuthenticatedHeader(envelope);
  assertByteArray(envelope.nonce, NONCE_BYTES, "invalid_nonce", "nonce");

  if (!(envelope.ciphertext instanceof Uint8Array)) {
    throw new ProtocolError(
      "invalid_argument",
      "ciphertext must be a Uint8Array",
    );
  }
  if (envelope.ciphertext.byteLength > MAX_CIPHERTEXT_BYTES) {
    throw new ProtocolError(
      "oversized_ciphertext",
      `ciphertext exceeds ${MAX_CIPHERTEXT_BYTES} bytes`,
    );
  }

  const frame = Buffer.alloc(
    FIXED_HEADER_BYTES + envelope.ciphertext.byteLength,
  );
  frame.set(authenticatedHeader, 0);
  frame.set(envelope.nonce, AUTHENTICATED_HEADER_BYTES);
  frame.writeUInt32BE(
    envelope.ciphertext.byteLength,
    CIPHERTEXT_LENGTH_OFFSET,
  );
  frame.set(envelope.ciphertext, FIXED_HEADER_BYTES);

  return `${WIRE_PREFIX}${frame.toString("base64url")}`;
}

function decodeCanonicalBase64Url(value: string): Buffer {
  if (value.length === 0 || !BASE64URL.test(value)) {
    throw new ProtocolError(
      "invalid_encoding",
      "Envelope payload must be unpadded base64url",
    );
  }

  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) {
    throw new ProtocolError(
      "invalid_encoding",
      "Envelope payload is not canonical base64url",
    );
  }
  return decoded;
}

export function decodeEnvelope(wire: string): Envelope {
  if (typeof wire !== "string") {
    throw new ProtocolError("invalid_argument", "wire must be a string");
  }
  if (!wire.startsWith(WIRE_PREFIX)) {
    throw new ProtocolError(
      "invalid_prefix",
      `Envelope must start with ${WIRE_PREFIX}`,
    );
  }

  const frame = decodeCanonicalBase64Url(wire.slice(WIRE_PREFIX.length));
  if (frame.byteLength < FIXED_HEADER_BYTES) {
    throw new ProtocolError("invalid_length", "Envelope header is truncated");
  }
  if (frame[0] !== MAGIC[0] || frame[1] !== MAGIC[1]) {
    throw new ProtocolError("invalid_magic", "Envelope magic is invalid");
  }

  const version = frame[2];
  const messageType = frame[3];
  const cipherSuite = frame.readUInt16BE(4);
  const flags = frame[6];
  const conversationId = Uint8Array.from(frame.subarray(7, 23));
  const senderDeviceId = Uint8Array.from(frame.subarray(23, 39));
  const sequence = frame.readBigUInt64BE(39);
  const nonce = Uint8Array.from(frame.subarray(47, 59));
  const ciphertextLength = frame.readUInt32BE(CIPHERTEXT_LENGTH_OFFSET);

  if (ciphertextLength > MAX_CIPHERTEXT_BYTES) {
    throw new ProtocolError(
      "oversized_ciphertext",
      `ciphertext exceeds ${MAX_CIPHERTEXT_BYTES} bytes`,
    );
  }
  if (frame.byteLength !== FIXED_HEADER_BYTES + ciphertextLength) {
    throw new ProtocolError(
      "invalid_length",
      "Ciphertext length does not match the envelope",
    );
  }

  const envelope = {
    version,
    messageType,
    cipherSuite,
    flags,
    conversationId,
    senderDeviceId,
    sequence,
    nonce,
    ciphertext: Uint8Array.from(frame.subarray(FIXED_HEADER_BYTES)),
  };

  validateAuthenticatedHeader(envelope as AuthenticatedHeader);

  return envelope as Envelope;
}
