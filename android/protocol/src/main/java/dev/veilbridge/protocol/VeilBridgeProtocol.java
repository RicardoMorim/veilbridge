/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package dev.veilbridge.protocol;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class VeilBridgeProtocol {
    public static final String WIRE_PREFIX = "vb1.";
    public static final int CONTENT_KEY_BYTES = 32;
    public static final int IDENTIFIER_BYTES = 16;
    public static final int NONCE_BYTES = 12;
    public static final int MAX_CIPHERTEXT_BYTES = 48 * 1024;
    public static final int MAX_PLAINTEXT_BYTES = MAX_CIPHERTEXT_BYTES - 16;

    private static final int PROTOCOL_VERSION = 1;
    private static final int MESSAGE_TYPE_DIRECT = 1;
    private static final int CIPHER_SUITE_AES_256_GCM = 1;
    private static final int AUTHENTICATED_HEADER_BYTES = 47;
    private static final int FIXED_HEADER_BYTES = 63;
    private static final int CIPHERTEXT_LENGTH_OFFSET = 59;
    private static final int GCM_TAG_BITS = 128;
    private static final BigInteger MAX_UINT64 =
            BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
    private static final Pattern BASE64URL = Pattern.compile("^[A-Za-z0-9_-]+$");

    private final SecureRandom secureRandom;

    public VeilBridgeProtocol() {
        this(new SecureRandom());
    }

    VeilBridgeProtocol(SecureRandom secureRandom) {
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
    }

    public byte[] generateContentKey() {
        byte[] contentKey = new byte[CONTENT_KEY_BYTES];
        secureRandom.nextBytes(contentKey);
        return contentKey;
    }

    public byte[] generateIdentifier() {
        byte[] identifier = new byte[IDENTIFIER_BYTES];
        secureRandom.nextBytes(identifier);
        return identifier;
    }

    public String encodeContentKey(byte[] contentKey) {
        byte[] keyCopy = copyContentKey(contentKey);
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(keyCopy);
        } finally {
            Arrays.fill(keyCopy, (byte) 0);
        }
    }

    public byte[] decodeContentKey(String encoded) {
        byte[] decoded = decodeCanonicalBase64Url(
                encoded,
                "invalid_content_key",
                "Content key must be canonical unpadded base64url");
        if (decoded.length != CONTENT_KEY_BYTES) {
            Arrays.fill(decoded, (byte) 0);
            throw new ProtocolException(
                    "invalid_content_key",
                    "Content key must decode to exactly " + CONTENT_KEY_BYTES + " bytes");
        }
        return decoded;
    }

    public String sealText(
            String plaintext,
            byte[] contentKey,
            MessageMetadata metadata) {
        if (plaintext == null) {
            throw new ProtocolException("invalid_argument", "Plaintext must not be null");
        }

        byte[] encoded = plaintext.getBytes(StandardCharsets.UTF_8);
        try {
            return sealBytes(encoded, contentKey, metadata);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    public String sealBytes(
            byte[] plaintext,
            byte[] contentKey,
            MessageMetadata metadata) {
        if (plaintext == null) {
            throw new ProtocolException("invalid_argument", "Plaintext must not be null");
        }
        if (metadata == null) {
            throw new ProtocolException("invalid_argument", "Metadata must not be null");
        }
        if (plaintext.length > MAX_PLAINTEXT_BYTES) {
            throw new ProtocolException(
                    "oversized_plaintext",
                    "Plaintext exceeds " + MAX_PLAINTEXT_BYTES + " bytes");
        }

        byte[] keyCopy = copyContentKey(contentKey);
        byte[] plaintextCopy = Arrays.copyOf(plaintext, plaintext.length);
        byte[] nonce = new byte[NONCE_BYTES];
        secureRandom.nextBytes(nonce);
        MessageMetadata stableMetadata = new MessageMetadata(
                metadata.getConversationId(),
                metadata.getSenderDeviceId(),
                metadata.getSequence());
        Envelope emptyEnvelope = new Envelope(
                PROTOCOL_VERSION,
                MESSAGE_TYPE_DIRECT,
                CIPHER_SUITE_AES_256_GCM,
                0,
                stableMetadata,
                nonce,
                new byte[0]);
        byte[] additionalData = encodeAuthenticatedHeader(emptyEnvelope);

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(keyCopy, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(additionalData);
            byte[] ciphertext = cipher.doFinal(plaintextCopy);
            return encodeEnvelope(new Envelope(
                    PROTOCOL_VERSION,
                    MESSAGE_TYPE_DIRECT,
                    CIPHER_SUITE_AES_256_GCM,
                    0,
                    stableMetadata,
                    nonce,
                    ciphertext));
        } catch (GeneralSecurityException error) {
            throw new ProtocolException(
                    "crypto_failure",
                    "The platform AES-GCM implementation failed",
                    error);
        } finally {
            Arrays.fill(keyCopy, (byte) 0);
            Arrays.fill(plaintextCopy, (byte) 0);
            Arrays.fill(additionalData, (byte) 0);
        }
    }

    public OpenedText openText(String wire, byte[] contentKey) {
        OpenedBytes opened = openBytes(wire, contentKey);
        byte[] plaintext = opened.getPlaintext();
        try {
            CharBuffer decoded = StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(plaintext));
            return new OpenedText(decoded.toString(), opened.getMetadata());
        } catch (CharacterCodingException error) {
            throw new ProtocolException(
                    "invalid_utf8",
                    "Plaintext is not valid UTF-8",
                    error);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    public OpenedBytes openBytes(String wire, byte[] contentKey) {
        Envelope envelope = decodeEnvelope(wire);
        byte[] ciphertext = envelope.getCiphertext();
        if (ciphertext.length < GCM_TAG_BITS / 8) {
            throw new ProtocolException(
                    "invalid_length",
                    "Ciphertext is shorter than the authentication tag");
        }

        byte[] keyCopy = copyContentKey(contentKey);
        byte[] nonce = envelope.getNonce();
        byte[] additionalData = encodeAuthenticatedHeader(envelope);
        byte[] plaintext = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(keyCopy, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(additionalData);
            plaintext = cipher.doFinal(ciphertext);
            return new OpenedBytes(plaintext, envelope.getMetadata());
        } catch (GeneralSecurityException error) {
            throw new ProtocolException(
                    "authentication_failed",
                    "Envelope authentication failed",
                    error);
        } finally {
            Arrays.fill(keyCopy, (byte) 0);
            Arrays.fill(ciphertext, (byte) 0);
            Arrays.fill(additionalData, (byte) 0);
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
    }

    public String encodeEnvelope(Envelope envelope) {
        byte[] authenticatedHeader = encodeAuthenticatedHeader(envelope);
        byte[] nonce = envelope.getNonce();
        byte[] ciphertext = envelope.getCiphertext();

        ByteBuffer frame = ByteBuffer
                .allocate(FIXED_HEADER_BYTES + ciphertext.length)
                .order(ByteOrder.BIG_ENDIAN);
        frame.put(authenticatedHeader);
        frame.put(nonce);
        frame.putInt(ciphertext.length);
        frame.put(ciphertext);

        return WIRE_PREFIX
                + Base64.getUrlEncoder().withoutPadding().encodeToString(frame.array());
    }

    public Envelope decodeEnvelope(String wire) {
        if (wire == null) {
            throw new ProtocolException("invalid_argument", "Wire must not be null");
        }
        if (!wire.startsWith(WIRE_PREFIX)) {
            throw new ProtocolException(
                    "invalid_prefix",
                    "Envelope must start with " + WIRE_PREFIX);
        }

        byte[] frame = decodeCanonicalBase64Url(
                wire.substring(WIRE_PREFIX.length()),
                "invalid_encoding",
                "Envelope payload must be canonical unpadded base64url");
        if (frame.length < FIXED_HEADER_BYTES) {
            throw new ProtocolException("invalid_length", "Envelope header is truncated");
        }
        if (frame[0] != 0x56 || frame[1] != 0x42) {
            throw new ProtocolException("invalid_magic", "Envelope magic is invalid");
        }

        int version = Byte.toUnsignedInt(frame[2]);
        int messageType = Byte.toUnsignedInt(frame[3]);
        int cipherSuite =
                (Byte.toUnsignedInt(frame[4]) << 8) | Byte.toUnsignedInt(frame[5]);
        int flags = Byte.toUnsignedInt(frame[6]);
        byte[] conversationId = Arrays.copyOfRange(frame, 7, 23);
        byte[] senderDeviceId = Arrays.copyOfRange(frame, 23, 39);
        BigInteger sequence =
                new BigInteger(1, Arrays.copyOfRange(frame, 39, 47));
        byte[] nonce = Arrays.copyOfRange(frame, 47, 59);
        long ciphertextLength = Integer.toUnsignedLong(
                ByteBuffer.wrap(frame, CIPHERTEXT_LENGTH_OFFSET, 4)
                        .order(ByteOrder.BIG_ENDIAN)
                        .getInt());

        if (ciphertextLength > MAX_CIPHERTEXT_BYTES) {
            throw new ProtocolException(
                    "oversized_ciphertext",
                    "Ciphertext exceeds " + MAX_CIPHERTEXT_BYTES + " bytes");
        }
        if (frame.length != FIXED_HEADER_BYTES + (int) ciphertextLength) {
            throw new ProtocolException(
                    "invalid_length",
                    "Ciphertext length does not match the envelope");
        }

        return new Envelope(
                version,
                messageType,
                cipherSuite,
                flags,
                new MessageMetadata(conversationId, senderDeviceId, sequence),
                nonce,
                Arrays.copyOfRange(frame, FIXED_HEADER_BYTES, frame.length));
    }

    private static byte[] encodeAuthenticatedHeader(Envelope envelope) {
        validateProtocolFields(
                envelope.getVersion(),
                envelope.getMessageType(),
                envelope.getCipherSuite(),
                envelope.getFlags());
        MessageMetadata metadata = envelope.getMetadata();

        ByteBuffer header = ByteBuffer
                .allocate(AUTHENTICATED_HEADER_BYTES)
                .order(ByteOrder.BIG_ENDIAN);
        header.put((byte) 0x56);
        header.put((byte) 0x42);
        header.put((byte) envelope.getVersion());
        header.put((byte) envelope.getMessageType());
        header.putShort((short) envelope.getCipherSuite());
        header.put((byte) envelope.getFlags());
        header.put(metadata.getConversationId());
        header.put(metadata.getSenderDeviceId());
        putUnsignedLong(header, metadata.getSequence());
        return header.array();
    }

    private static void putUnsignedLong(ByteBuffer target, BigInteger value) {
        byte[] encoded = value.toByteArray();
        int sourceOffset = encoded.length == 9 && encoded[0] == 0 ? 1 : 0;
        int length = encoded.length - sourceOffset;
        for (int padding = length; padding < 8; padding++) {
            target.put((byte) 0);
        }
        target.put(encoded, sourceOffset, length);
    }

    private static byte[] copyContentKey(byte[] contentKey) {
        if (contentKey == null || contentKey.length != CONTENT_KEY_BYTES) {
            throw new ProtocolException(
                    "invalid_content_key",
                    "Content key must be exactly " + CONTENT_KEY_BYTES + " bytes");
        }
        return Arrays.copyOf(contentKey, contentKey.length);
    }

    private static byte[] decodeCanonicalBase64Url(
            String encoded,
            String code,
            String message) {
        if (encoded == null
                || encoded.isEmpty()
                || !BASE64URL.matcher(encoded).matches()) {
            throw new ProtocolException(code, message);
        }

        try {
            byte[] decoded = Base64.getUrlDecoder().decode(encoded);
            String canonical =
                    Base64.getUrlEncoder().withoutPadding().encodeToString(decoded);
            if (!canonical.equals(encoded)) {
                Arrays.fill(decoded, (byte) 0);
                throw new ProtocolException(code, message);
            }
            return decoded;
        } catch (IllegalArgumentException error) {
            throw new ProtocolException(code, message, error);
        }
    }

    private static void validateProtocolFields(
            int version,
            int messageType,
            int cipherSuite,
            int flags) {
        if (version != PROTOCOL_VERSION) {
            throw new ProtocolException(
                    "unsupported_version",
                    "Unsupported envelope version: " + version);
        }
        if (messageType != MESSAGE_TYPE_DIRECT) {
            throw new ProtocolException(
                    "unsupported_message_type",
                    "Unsupported message type: " + messageType);
        }
        if (cipherSuite != CIPHER_SUITE_AES_256_GCM) {
            throw new ProtocolException(
                    "unsupported_cipher_suite",
                    "Unsupported cipher suite: " + cipherSuite);
        }
        if (flags != 0) {
            throw new ProtocolException(
                    "unsupported_flags",
                    "Unsupported critical flags: " + flags);
        }
    }

    private static byte[] copyExact(
            byte[] value,
            int expectedLength,
            String code,
            String label) {
        if (value == null || value.length != expectedLength) {
            throw new ProtocolException(
                    code,
                    label + " must be exactly " + expectedLength + " bytes");
        }
        return Arrays.copyOf(value, value.length);
    }

    public static final class MessageMetadata {
        private final byte[] conversationId;
        private final byte[] senderDeviceId;
        private final BigInteger sequence;

        public MessageMetadata(
                byte[] conversationId,
                byte[] senderDeviceId,
                BigInteger sequence) {
            this.conversationId = copyExact(
                    conversationId,
                    IDENTIFIER_BYTES,
                    "invalid_identifier",
                    "conversationId");
            this.senderDeviceId = copyExact(
                    senderDeviceId,
                    IDENTIFIER_BYTES,
                    "invalid_identifier",
                    "senderDeviceId");
            if (sequence == null
                    || sequence.signum() < 0
                    || sequence.compareTo(MAX_UINT64) > 0) {
                throw new ProtocolException(
                        "invalid_sequence",
                        "Sequence must be an unsigned 64-bit integer");
            }
            this.sequence = sequence;
        }

        public byte[] getConversationId() {
            return Arrays.copyOf(conversationId, conversationId.length);
        }

        public byte[] getSenderDeviceId() {
            return Arrays.copyOf(senderDeviceId, senderDeviceId.length);
        }

        public BigInteger getSequence() {
            return sequence;
        }
    }

    public static final class Envelope {
        private final int version;
        private final int messageType;
        private final int cipherSuite;
        private final int flags;
        private final MessageMetadata metadata;
        private final byte[] nonce;
        private final byte[] ciphertext;

        public Envelope(
                int version,
                int messageType,
                int cipherSuite,
                int flags,
                MessageMetadata metadata,
                byte[] nonce,
                byte[] ciphertext) {
            validateProtocolFields(version, messageType, cipherSuite, flags);
            this.version = version;
            this.messageType = messageType;
            this.cipherSuite = cipherSuite;
            this.flags = flags;
            this.metadata = Objects.requireNonNull(metadata, "metadata");
            this.nonce = copyExact(
                    nonce,
                    NONCE_BYTES,
                    "invalid_nonce",
                    "nonce");
            if (ciphertext == null) {
                throw new ProtocolException(
                        "invalid_argument",
                        "Ciphertext must not be null");
            }
            if (ciphertext.length > MAX_CIPHERTEXT_BYTES) {
                throw new ProtocolException(
                        "oversized_ciphertext",
                        "Ciphertext exceeds " + MAX_CIPHERTEXT_BYTES + " bytes");
            }
            this.ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
        }

        public int getVersion() {
            return version;
        }

        public int getMessageType() {
            return messageType;
        }

        public int getCipherSuite() {
            return cipherSuite;
        }

        public int getFlags() {
            return flags;
        }

        public MessageMetadata getMetadata() {
            return new MessageMetadata(
                    metadata.getConversationId(),
                    metadata.getSenderDeviceId(),
                    metadata.getSequence());
        }

        public byte[] getNonce() {
            return Arrays.copyOf(nonce, nonce.length);
        }

        public byte[] getCiphertext() {
            return Arrays.copyOf(ciphertext, ciphertext.length);
        }
    }

    public static final class OpenedBytes {
        private final byte[] plaintext;
        private final MessageMetadata metadata;

        private OpenedBytes(byte[] plaintext, MessageMetadata metadata) {
            this.plaintext = Arrays.copyOf(plaintext, plaintext.length);
            this.metadata = metadata;
        }

        public byte[] getPlaintext() {
            return Arrays.copyOf(plaintext, plaintext.length);
        }

        public MessageMetadata getMetadata() {
            return new MessageMetadata(
                    metadata.getConversationId(),
                    metadata.getSenderDeviceId(),
                    metadata.getSequence());
        }
    }

    public static final class OpenedText {
        private final String plaintext;
        private final MessageMetadata metadata;

        private OpenedText(String plaintext, MessageMetadata metadata) {
            this.plaintext = plaintext;
            this.metadata = metadata;
        }

        public String getPlaintext() {
            return plaintext;
        }

        public MessageMetadata getMetadata() {
            return new MessageMetadata(
                    metadata.getConversationId(),
                    metadata.getSenderDeviceId(),
                    metadata.getSequence());
        }
    }
}
