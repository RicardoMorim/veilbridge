import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  ProtocolError,
  decodeEnvelope,
  generateContentKey,
  openBytes,
  openText,
  sealBytes,
  sealText,
} from "../src/index.js";

const metadata = {
  conversationId: Uint8Array.from({ length: 16 }, (_, index) => index),
  senderDeviceId: Uint8Array.from(
    { length: 16 },
    (_, index) => 0xf0 + index,
  ),
  sequence: 7n,
};

function mutateWire(
  wire: string,
  mutation: (bytes: Uint8Array) => void,
): string {
  const bytes = Buffer.from(wire.slice("vb1.".length), "base64url");
  mutation(bytes);
  return `vb1.${bytes.toString("base64url")}`;
}

test("seals text without exposing plaintext to the carrier frame", async () => {
  const key = generateContentKey();
  const plaintext = "This sentence must stay out of the host messenger.";

  const wire = await sealText(plaintext, key, metadata);
  const rawFrame = Buffer.from(wire.slice("vb1.".length), "base64url");
  const opened = await openText(wire, key);

  assert.equal(wire.startsWith("vb1."), true);
  assert.equal(rawFrame.includes(Buffer.from(plaintext, "utf8")), false);
  assert.equal(opened.plaintext, plaintext);
  assert.deepEqual(opened.metadata.conversationId, metadata.conversationId);
  assert.deepEqual(opened.metadata.senderDeviceId, metadata.senderDeviceId);
  assert.equal(opened.metadata.sequence, metadata.sequence);
});

test("uses a fresh nonce for each seal", async () => {
  const key = generateContentKey();
  const first = await sealText("same text", key, metadata);
  const second = await sealText("same text", key, metadata);

  assert.notDeepEqual(decodeEnvelope(first).nonce, decodeEnvelope(second).nonce);
  assert.notEqual(first, second);
});

test("fails authentication with the wrong content key", async () => {
  const wire = await sealText("private", generateContentKey(), metadata);

  await assert.rejects(
    () => openText(wire, generateContentKey()),
    (error: unknown) =>
      error instanceof ProtocolError && error.code === "authentication_failed",
  );
});

test("authenticates conversation, sender-device, and sequence metadata", async () => {
  const key = generateContentKey();
  const wire = await sealText("bound to its metadata", key, metadata);
  const protectedOffsets = [7, 23, 46];

  for (const offset of protectedOffsets) {
    const tampered = mutateWire(wire, (bytes) => {
      bytes[offset] ^= 1;
    });

    await assert.rejects(
      () => openText(tampered, key),
      (error: unknown) =>
        error instanceof ProtocolError &&
        error.code === "authentication_failed",
    );
  }
});

test("fails authentication when ciphertext is modified", async () => {
  const key = generateContentKey();
  const wire = await sealText("authenticated", key, metadata);
  const tampered = mutateWire(wire, (bytes) => {
    bytes[bytes.length - 1] ^= 1;
  });

  await assert.rejects(
    () => openText(tampered, key),
    (error: unknown) =>
      error instanceof ProtocolError && error.code === "authentication_failed",
  );
});

test("rejects an incorrectly sized content key", async () => {
  await assert.rejects(
    () => sealText("private", new Uint8Array(16), metadata),
    (error: unknown) =>
      error instanceof ProtocolError && error.code === "invalid_content_key",
  );
});

test("rejects non-byte metadata instead of coercing it", async () => {
  await assert.rejects(
    () =>
      sealText("private", generateContentKey(), {
        ...metadata,
        senderDeviceId:
          "0123456789abcdef" as unknown as typeof metadata.senderDeviceId,
      }),
    (error: unknown) =>
      error instanceof ProtocolError && error.code === "invalid_identifier",
  );
});

test("authenticates bytes before performing strict UTF-8 decoding", async () => {
  const key = generateContentKey();
  const wire = await sealBytes(Uint8Array.of(0xff), key, metadata);
  const openedBytes = await openBytes(wire, key);

  assert.deepEqual(openedBytes.plaintext, Uint8Array.of(0xff));
  await assert.rejects(
    () => openText(wire, key),
    (error: unknown) =>
      error instanceof ProtocolError && error.code === "invalid_utf8",
  );
});

test("opens the published Android interoperability vector", async () => {
  const vectorUrl = new URL(
    "../../../test-vectors/content-key-v1.json",
    import.meta.url,
  );
  const vector = JSON.parse(await readFile(vectorUrl, "utf8")) as {
    contentKeyHex: string;
    plaintextUtf8: string;
    wire: string;
    fields: {
      conversationIdHex: string;
      senderDeviceIdHex: string;
      sequence: string;
    };
  };
  const key = Uint8Array.from(Buffer.from(vector.contentKeyHex, "hex"));

  const opened = await openText(vector.wire, key);

  assert.equal(opened.plaintext, vector.plaintextUtf8);
  assert.deepEqual(
    opened.metadata.conversationId,
    Uint8Array.from(Buffer.from(vector.fields.conversationIdHex, "hex")),
  );
  assert.deepEqual(
    opened.metadata.senderDeviceId,
    Uint8Array.from(Buffer.from(vector.fields.senderDeviceIdHex, "hex")),
  );
  assert.equal(opened.metadata.sequence, BigInt(vector.fields.sequence));
});
