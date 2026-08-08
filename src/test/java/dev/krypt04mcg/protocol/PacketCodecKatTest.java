package dev.krypt04mcg.protocol;

import dev.krypt04mcg.model.AlgorithmSuite;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.PacketType;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

final class PacketCodecKatTest {
    @Test
    void packetEncodingMatchesKnownAnswerVector() {
        PacketCodec codec = new PacketCodec();
        EncryptedPacket packet = knownPacket();

        byte[] encoded = codec.encode(packet);
        EncryptedPacket decoded = codec.decode(encoded);

        assertArrayEquals(manualEncode(packet), encoded);
        assertEquals(packet.sender(), decoded.sender());
        assertEquals(packet.receiver(), decoded.receiver());
        assertArrayEquals(packet.nonce(), decoded.nonce());
        assertArrayEquals(packet.ciphertext(), decoded.ciphertext());
        assertArrayEquals(packet.signature(), decoded.signature());
    }

    @Test
    void aadEncodingMatchesManualDifferentialVector() {
        PacketCodec codec = new PacketCodec();
        EncryptedPacket packet = knownPacket();

        assertArrayEquals(manualAad(packet), codec.aadFor(packet));
    }

    @Test
    void versionTwoAuthenticatesHkdfIdentifierWhileVersionOneStaysCompatible() {
        PacketCodec codec = new PacketCodec();
        EncryptedPacket legacy = knownPacket();
        EncryptedPacket current = new EncryptedPacket(EncryptedPacket.VERSION, legacy.type(), legacy.flags(),
                legacy.sender(), legacy.receiver(), legacy.timestampMillis(), legacy.messageId(),
                legacy.aadFragmentIndex(), legacy.aadFragmentTotal(), legacy.algorithms(), legacy.nonce(),
                legacy.kemCiphertext(), legacy.ciphertext(), legacy.signature());

        assertArrayEquals(manualAad(legacy), codec.aadFor(legacy));
        assertArrayEquals(manualAad(current), codec.aadFor(current));
        assertEquals(codec.aadFor(legacy).length + 2 + legacy.algorithms().hkdf().length(),
                codec.aadFor(current).length);
    }

    @Test
    void signatureInputAppendsTimestampNonceKemCiphertextWithoutSignature() throws Exception {
        PacketCodec codec = new PacketCodec();
        EncryptedPacket packet = knownPacket();
        ByteArrayOutputStream expected = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(expected);
        out.write(manualAad(packet));
        out.writeLong(packet.timestampMillis());
        writeBytes16(out, packet.nonce());
        writeBytes32(out, packet.kemCiphertext());
        writeBytes32(out, packet.ciphertext());

        assertArrayEquals(expected.toByteArray(), codec.signatureInput(packet));
    }

    private static EncryptedPacket knownPacket() {
        return new EncryptedPacket((byte) 1, PacketType.SIGNED_KEM_MESSAGE, (byte) 1,
                "alice", "bob", 123L, bytes(16, 7), (short) 2, (short) 9, AlgorithmSuite.defaults(),
                bytes(12, 1), bytes(32, 2), bytes(64, 3), bytes(48, 4));
    }

    private static byte[] manualEncode(EncryptedPacket packet) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeByte(packet.protocolVersion());
            out.writeByte(packet.type().id());
            out.writeByte(packet.flags());
            writeString(out, packet.sender());
            writeString(out, packet.receiver());
            out.writeLong(packet.timestampMillis());
            out.write(packet.messageId());
            out.writeShort(packet.aadFragmentIndex());
            out.writeShort(packet.aadFragmentTotal());
            writeString(out, packet.algorithms().kem());
            writeString(out, packet.algorithms().signature());
            writeString(out, packet.algorithms().aead());
            writeString(out, packet.algorithms().hkdf());
            writeBytes16(out, packet.nonce());
            writeBytes32(out, packet.kemCiphertext());
            writeBytes32(out, packet.ciphertext());
            writeBytes32(out, packet.signature());
            return bytes.toByteArray();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static byte[] manualAad(EncryptedPacket packet) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeByte(packet.protocolVersion());
            out.writeByte(packet.type().id());
            out.writeByte(packet.flags());
            writeString(out, packet.sender());
            writeString(out, packet.receiver());
            out.write(packet.messageId());
            out.writeShort(packet.aadFragmentIndex());
            out.writeShort(packet.aadFragmentTotal());
            writeString(out, packet.algorithms().kem());
            writeString(out, packet.algorithms().signature());
            writeString(out, packet.algorithms().aead());
            if (packet.protocolVersion() >= EncryptedPacket.VERSION) {
                writeString(out, packet.algorithms().hkdf());
            }
            return bytes.toByteArray();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static void writeString(DataOutputStream out, String value) throws Exception {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        out.writeShort(encoded.length);
        out.write(encoded);
    }

    private static void writeBytes16(DataOutputStream out, byte[] bytes) throws Exception {
        out.writeShort(bytes.length);
        out.write(bytes);
    }

    private static void writeBytes32(DataOutputStream out, byte[] bytes) throws Exception {
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private static byte[] bytes(int length, int value) {
        byte[] bytes = new byte[length];
        java.util.Arrays.fill(bytes, (byte) value);
        return bytes;
    }
}
