import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  CipherSuite,
  MAX_CIPHERTEXT_BYTES,
  MessageType,
  ProtocolError,
  decodeEnvelope,
  encodeEnvelope,
} from "../src/index.js";

const conversationId = Uint8Array.from({ length: 16 }, (_, index) => index);
const senderDeviceId = Uint8Array.from(
  { length: 16 },
  (_, index) => index + 16,
);
const nonce = Uint8Array.from({ length: 12 }, (_, index) => index + 32);
const ciphertext = Uint8Array.from([0xde, 0xad, 0xbe, 0xef]);

function validEnvelope() {
  return {
    version: 1 as const,
    messageType: MessageType.Direct,
    cipherSuite: CipherSuite.Aes256GcmContentKey,
    flags: 0,
    conversationId,
    senderDeviceId,
    sequence: 42n,
    nonce,
    ciphertext,
  };
}

function mutateWire(
  wire: string,
  mutation: (bytes: Uint8Array) => void,
): string {
  const bytes = Buffer.from(wire.slice("vb1.".length), "base64url");
  mutation(bytes);
  return `vb1.${bytes.toString("base64url")}`;
}

test("encodes the published v1 framing vector exactly", async () => {
  const vectorUrl = new URL("../../../test-vectors/envelope-v1.json", import.meta.url);
  const vector = JSON.parse(await readFile(vectorUrl, "utf8")) as {
    wire: string;
  };

  assert.equal(encodeEnvelope(validEnvelope()), vector.wire);
});

test("decodes every v1 field without sharing mutable input buffers", () => {
  const wire = encodeEnvelope(validEnvelope());
  const decoded = decodeEnvelope(wire);

  assert.equal(decoded.version, 1);
  assert.equal(decoded.messageType, MessageType.Direct);
  assert.equal(decoded.cipherSuite, CipherSuite.Aes256GcmContentKey);
  assert.equal(decoded.flags, 0);
  assert.deepEqual(decoded.conversationId, conversationId);
  assert.deepEqual(decoded.senderDeviceId, senderDeviceId);
  assert.equal(decoded.sequence, 42n);
  assert.deepEqual(decoded.nonce, nonce);
  assert.deepEqual(decoded.ciphertext, ciphertext);

  conversationId[0] = 0xff;
  assert.equal(decoded.conversationId[0], 0);
});

test("rejects an invalid identifier length", () => {
  assert.throws(
    () =>
      encodeEnvelope({
        ...validEnvelope(),
        conversationId: new Uint8Array(15),
      }),
    (error: unknown) =>
      error instanceof ProtocolError && error.code === "invalid_identifier",
  );
});

test("rejects a sequence outside the unsigned 64-bit range", () => {
  assert.throws(
    () =>
      encodeEnvelope({
        ...validEnvelope(),
        sequence: 1n << 64n,
      }),
    (error: unknown) =>
      error instanceof ProtocolError && error.code === "invalid_sequence",
  );
});

test("rejects ciphertext above the parser limit", () => {
  assert.throws(
    () =>
      encodeEnvelope({
        ...validEnvelope(),
        ciphertext: new Uint8Array(MAX_CIPHERTEXT_BYTES + 1),
      }),
    (error: unknown) =>
      error instanceof ProtocolError && error.code === "oversized_ciphertext",
  );
});

test("rejects non-canonical base64url and the wrong prefix", () => {
  assert.throws(
    () => decodeEnvelope("vb1.***"),
    (error: unknown) =>
      error instanceof ProtocolError && error.code === "invalid_encoding",
  );
  assert.throws(
    () => decodeEnvelope("vb2.AA"),
    (error: unknown) =>
      error instanceof ProtocolError && error.code === "invalid_prefix",
  );
});

test("rejects unsupported versions, types, suites, and critical flags", () => {
  const wire = encodeEnvelope(validEnvelope());

  const cases: Array<[number, number, ProtocolError["code"]]> = [
    [2, 2, "unsupported_version"],
    [3, 2, "unsupported_message_type"],
    [5, 2, "unsupported_cipher_suite"],
    [6, 1, "unsupported_flags"],
  ];

  for (const [offset, value, expectedCode] of cases) {
    assert.throws(
      () =>
        decodeEnvelope(
          mutateWire(wire, (bytes) => {
            bytes[offset] = value;
          }),
        ),
      (error: unknown) =>
        error instanceof ProtocolError && error.code === expectedCode,
    );
  }
});

test("rejects truncated and length-confused frames", () => {
  const wire = encodeEnvelope(validEnvelope());
  const truncated = mutateWire(wire, (bytes) => {
    bytes.set(bytes.subarray(0, bytes.length - 1));
  });
  const wrongLength = mutateWire(wire, (bytes) => {
    bytes[62] = 5;
  });

  assert.throws(
    () => decodeEnvelope(truncated.slice(0, -2)),
    (error: unknown) =>
      error instanceof ProtocolError && error.code === "invalid_length",
  );
  assert.throws(
    () => decodeEnvelope(wrongLength),
    (error: unknown) =>
      error instanceof ProtocolError && error.code === "invalid_length",
  );
});
