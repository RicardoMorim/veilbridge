/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package dev.veilbridge.protocol;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.Test;

public final class VeilBridgeProtocolTest {
    private static final byte[] CONTENT_KEY = bytes(0, 32);
    private static final byte[] CONVERSATION_ID = bytes(0, 16);
    private static final byte[] SENDER_DEVICE_ID = bytes(16, 16);
    private static final byte[] NONCE = bytes(32, 12);
    private static final String FRAME_VECTOR =
            "vb1.VkIBAQABAAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
                    + "AAAAAAAAACogISIjJCUmJygpKisAAAAE3q2-7w";
    private static final String CONTENT_KEY_VECTOR =
            "vb1.VkIBAQABAAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
                    + "AAAAAAAAACogISIjJCUmJygpKisAAAAiul_KHAO4fHx1EWKvr3yGl"
                    + "rktZR-z6KvHY-bt-gKqDNVcdg";

    private static VeilBridgeProtocol.MessageMetadata metadata() {
        return new VeilBridgeProtocol.MessageMetadata(
                CONVERSATION_ID,
                SENDER_DEVICE_ID,
                BigInteger.valueOf(42));
    }

    @Test
    public void encodesPublishedFramingVectorExactly() {
        VeilBridgeProtocol protocol = new VeilBridgeProtocol();
        VeilBridgeProtocol.Envelope envelope = new VeilBridgeProtocol.Envelope(
                1,
                1,
                1,
                0,
                metadata(),
                NONCE,
                hex("deadbeef"));

        assertEquals(FRAME_VECTOR, protocol.encodeEnvelope(envelope));
    }

    @Test
    public void sealsPublishedCrossLanguageCipherVectorExactly() {
        VeilBridgeProtocol protocol =
                new VeilBridgeProtocol(new FixedSecureRandom(NONCE));

        String wire = protocol.sealText(
                "hello from android",
                CONTENT_KEY,
                metadata());

        assertEquals(CONTENT_KEY_VECTOR, wire);
    }

    @Test
    public void opensPublishedCrossLanguageCipherVector() {
        VeilBridgeProtocol.OpenedText opened =
                new VeilBridgeProtocol().openText(CONTENT_KEY_VECTOR, CONTENT_KEY);

        assertEquals("hello from android", opened.getPlaintext());
        assertArrayEquals(CONVERSATION_ID, opened.getMetadata().getConversationId());
        assertArrayEquals(SENDER_DEVICE_ID, opened.getMetadata().getSenderDeviceId());
        assertEquals(BigInteger.valueOf(42), opened.getMetadata().getSequence());
    }

    @Test
    public void roundTripDoesNotExposePlaintextAndUsesFreshNonces() {
        VeilBridgeProtocol protocol = new VeilBridgeProtocol();
        String plaintext = "the host messenger must not see this";

        String first = protocol.sealText(plaintext, CONTENT_KEY, metadata());
        String second = protocol.sealText(plaintext, CONTENT_KEY, metadata());

        assertTrue(first.startsWith("vb1."));
        assertFalse(first.contains(plaintext));
        assertNotEquals(first, second);
        assertEquals(plaintext, protocol.openText(first, CONTENT_KEY).getPlaintext());
    }

    @Test
    public void rejectsWrongKeyAndTamperingWithoutLeakingWhichFailed() {
        VeilBridgeProtocol protocol = new VeilBridgeProtocol();
        String wire = protocol.sealText("private", CONTENT_KEY, metadata());

        ProtocolException wrongKey = assertThrows(
                ProtocolException.class,
                () -> protocol.openText(wire, bytes(1, 32)));
        assertEquals("authentication_failed", wrongKey.getCode());

        byte[] frame = java.util.Base64.getUrlDecoder().decode(wire.substring(4));
        frame[frame.length - 1] ^= 1;
        String tampered =
                "vb1." + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(frame);
        ProtocolException corrupted = assertThrows(
                ProtocolException.class,
                () -> protocol.openText(tampered, CONTENT_KEY));
        assertEquals("authentication_failed", corrupted.getCode());
    }

    @Test
    public void rejectsInvalidKeysAndNonCanonicalFrames() {
        VeilBridgeProtocol protocol = new VeilBridgeProtocol();

        ProtocolException badKey = assertThrows(
                ProtocolException.class,
                () -> protocol.sealText("private", new byte[16], metadata()));
        assertEquals("invalid_content_key", badKey.getCode());

        ProtocolException badPrefix = assertThrows(
                ProtocolException.class,
                () -> protocol.decodeEnvelope("vb2.AA"));
        assertEquals("invalid_prefix", badPrefix.getCode());

        ProtocolException padded = assertThrows(
                ProtocolException.class,
                () -> protocol.decodeEnvelope(FRAME_VECTOR + "="));
        assertEquals("invalid_encoding", padded.getCode());
    }

    @Test
    public void keyTextEncodingIsCanonicalAndRoundTrips() {
        VeilBridgeProtocol protocol = new VeilBridgeProtocol();

        String encoded = protocol.encodeContentKey(CONTENT_KEY);

        assertFalse(encoded.contains("="));
        assertArrayEquals(CONTENT_KEY, protocol.decodeContentKey(encoded));
        assertThrows(
                ProtocolException.class,
                () -> protocol.decodeContentKey(encoded + "="));
    }

    private static byte[] bytes(int start, int length) {
        byte[] result = new byte[length];
        for (int index = 0; index < length; index++) {
            result[index] = (byte) (start + index);
        }
        return result;
    }

    private static byte[] hex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int index = 0; index < result.length; index++) {
            result[index] = (byte) Integer.parseInt(
                    value.substring(index * 2, index * 2 + 2),
                    16);
        }
        return result;
    }

    private static final class FixedSecureRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;

        private final byte[] bytes;

        private FixedSecureRandom(byte[] bytes) {
            this.bytes = Arrays.copyOf(bytes, bytes.length);
        }

        @Override
        public void nextBytes(byte[] target) {
            if (target.length != bytes.length) {
                throw new AssertionError("unexpected random byte request");
            }
            System.arraycopy(bytes, 0, target, 0, target.length);
        }
    }
}
