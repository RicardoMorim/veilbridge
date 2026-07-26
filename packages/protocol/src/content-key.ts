/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

import { randomBytes, webcrypto } from "node:crypto";

import { ProtocolError } from "./errors.js";
import {
  CipherSuite,
  MAX_CIPHERTEXT_BYTES,
  MessageType,
  NONCE_BYTES,
  PROTOCOL_VERSION,
  decodeEnvelope,
  encodeAuthenticatedHeader,
  encodeEnvelope,
  type Envelope,
  type MessageMetadata,
} from "./framing.js";

const CONTENT_KEY_BYTES = 32;
const GCM_TAG_BYTES = 16;
const MAX_PLAINTEXT_BYTES = MAX_CIPHERTEXT_BYTES - GCM_TAG_BYTES;
const subtle = webcrypto.subtle;

export interface OpenedBytes {
  plaintext: Uint8Array;
  metadata: MessageMetadata;
}

export interface OpenedText {
  plaintext: string;
  metadata: MessageMetadata;
}

function copyContentKey(contentKey: Uint8Array): Uint8Array {
  if (
    !(contentKey instanceof Uint8Array) ||
    contentKey.byteLength !== CONTENT_KEY_BYTES
  ) {
    throw new ProtocolError(
      "invalid_content_key",
      `content key must be exactly ${CONTENT_KEY_BYTES} bytes`,
    );
  }
  return Uint8Array.from(contentKey);
}

function copyMetadata(metadata: MessageMetadata): MessageMetadata {
  if (typeof metadata !== "object" || metadata === null) {
    throw new ProtocolError("invalid_argument", "metadata must be an object");
  }

  return {
    conversationId: Uint8Array.from(metadata.conversationId),
    senderDeviceId: Uint8Array.from(metadata.senderDeviceId),
    sequence: metadata.sequence,
  };
}

function envelopeFor(
  metadata: MessageMetadata,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Envelope {
  return {
    version: PROTOCOL_VERSION,
    messageType: MessageType.Direct,
    cipherSuite: CipherSuite.Aes256GcmContentKey,
    flags: 0,
    conversationId: metadata.conversationId,
    senderDeviceId: metadata.senderDeviceId,
    sequence: metadata.sequence,
    nonce,
    ciphertext,
  };
}

async function importContentKey(
  contentKey: Uint8Array,
  usage: "encrypt" | "decrypt",
): Promise<webcrypto.CryptoKey> {
  return subtle.importKey(
    "raw",
    contentKey,
    { name: "AES-GCM" },
    false,
    [usage],
  );
}

export function generateContentKey(): Uint8Array {
  return Uint8Array.from(randomBytes(CONTENT_KEY_BYTES));
}

export async function sealBytes(
  plaintext: Uint8Array,
  contentKey: Uint8Array,
  metadata: MessageMetadata,
): Promise<string> {
  if (!(plaintext instanceof Uint8Array)) {
    throw new ProtocolError(
      "invalid_argument",
      "plaintext must be a Uint8Array",
    );
  }
  if (plaintext.byteLength > MAX_PLAINTEXT_BYTES) {
    throw new ProtocolError(
      "oversized_plaintext",
      `plaintext exceeds ${MAX_PLAINTEXT_BYTES} bytes`,
    );
  }

  const keyBytes = copyContentKey(contentKey);
  const stableMetadata = copyMetadata(metadata);
  const nonce = Uint8Array.from(randomBytes(NONCE_BYTES));
  const plaintextCopy = Uint8Array.from(plaintext);
  const emptyEnvelope = envelopeFor(stableMetadata, nonce, new Uint8Array());
  const additionalData = encodeAuthenticatedHeader(emptyEnvelope);

  try {
    const key = await importContentKey(keyBytes, "encrypt");
    const encrypted = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData,
        tagLength: GCM_TAG_BYTES * 8,
      },
      key,
      plaintextCopy,
    );

    return encodeEnvelope(
      envelopeFor(stableMetadata, nonce, new Uint8Array(encrypted)),
    );
  } finally {
    keyBytes.fill(0);
    plaintextCopy.fill(0);
  }
}

export async function sealText(
  plaintext: string,
  contentKey: Uint8Array,
  metadata: MessageMetadata,
): Promise<string> {
  if (typeof plaintext !== "string") {
    throw new ProtocolError("invalid_argument", "plaintext must be a string");
  }

  const encoded = new TextEncoder().encode(plaintext);
  try {
    return await sealBytes(encoded, contentKey, metadata);
  } finally {
    encoded.fill(0);
  }
}

export async function openBytes(
  wire: string,
  contentKey: Uint8Array,
): Promise<OpenedBytes> {
  const envelope = decodeEnvelope(wire);
  if (envelope.ciphertext.byteLength < GCM_TAG_BYTES) {
    throw new ProtocolError(
      "invalid_length",
      "Ciphertext is shorter than the authentication tag",
    );
  }

  const keyBytes = copyContentKey(contentKey);
  const additionalData = encodeAuthenticatedHeader(envelope);

  try {
    const key = await importContentKey(keyBytes, "decrypt");
    const decrypted = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: envelope.nonce,
        additionalData,
        tagLength: GCM_TAG_BYTES * 8,
      },
      key,
      envelope.ciphertext,
    );

    return {
      plaintext: new Uint8Array(decrypted),
      metadata: {
        conversationId: Uint8Array.from(envelope.conversationId),
        senderDeviceId: Uint8Array.from(envelope.senderDeviceId),
        sequence: envelope.sequence,
      },
    };
  } catch {
    throw new ProtocolError(
      "authentication_failed",
      "Envelope authentication failed",
    );
  } finally {
    keyBytes.fill(0);
  }
}

export async function openText(
  wire: string,
  contentKey: Uint8Array,
): Promise<OpenedText> {
  const opened = await openBytes(wire, contentKey);

  try {
    return {
      plaintext: new TextDecoder("utf-8", { fatal: true }).decode(
        opened.plaintext,
      ),
      metadata: opened.metadata,
    };
  } catch {
    throw new ProtocolError("invalid_utf8", "Plaintext is not valid UTF-8");
  } finally {
    opened.plaintext.fill(0);
  }
}
