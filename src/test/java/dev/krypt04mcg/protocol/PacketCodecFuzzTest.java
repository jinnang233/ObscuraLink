package dev.krypt04mcg.protocol;

import dev.krypt04mcg.model.AlgorithmSuite;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.PacketType;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class PacketCodecFuzzTest {
    private static final SecureRandom SEED_RANDOM = new SecureRandom();
    private static final int CASES = 250;

    @Test
    void randomizedPacketsRoundTrip() {
        PacketCodec codec = new PacketCodec();
        Random random = random("randomizedPacketsRoundTrip");

        for (int i = 0; i < CASES; i++) {
            EncryptedPacket packet = randomPacket(random);

            EncryptedPacket decoded = codec.decode(codec.encode(packet));

            assertPacketEquals(packet, decoded);
        }
    }

    @Test
    void truncatedPacketsAreRejected() {
        PacketCodec codec = new PacketCodec();
        Random random = random("truncatedPacketsAreRejected");

        for (int i = 0; i < CASES; i++) {
            byte[] encoded = codec.encode(randomPacket(random));
            int cut = random.nextInt(encoded.length);
            byte[] truncated = Arrays.copyOf(encoded, cut);

            assertThrows(IllegalArgumentException.class, () -> codec.decode(truncated));
        }
    }

    @Test
    void oversizedLengthFieldsAreRejectedBeforeAllocation() throws Exception {
        PacketCodec codec = new PacketCodec();
        Random random = random("oversizedLengthFieldsAreRejectedBeforeAllocation");

        for (int i = 0; i < CASES; i++) {
            byte[] encoded = random.nextBoolean()
                    ? packetWithOversizedSender(random)
                    : packetWithOversizedKemCiphertext(random);

            assertThrows(IllegalArgumentException.class, () -> codec.decode(encoded));
        }
    }

    private static EncryptedPacket randomPacket(Random random) {
        PacketType[] types = PacketType.values();
        byte version = random.nextBoolean() ? EncryptedPacket.LEGACY_VERSION : EncryptedPacket.VERSION;
        PacketType type = types[random.nextInt(types.length)];
        byte flags = (byte) random.nextInt(256);
        AlgorithmSuite algorithms = randomAlgorithms(random);
        short fragmentIndex = (short) random.nextInt(Short.MAX_VALUE + 1);
        short fragmentTotal = (short) (1 + random.nextInt(Short.MAX_VALUE));
        byte[] signature = randomBytes(random, random.nextInt(129));
        if (version >= EncryptedPacket.VERSION) {
            fragmentIndex = 0;
            fragmentTotal = 1;
            algorithms = new AlgorithmSuite(type == PacketType.SESSION_MESSAGE ? "NONE" : algorithms.kem(),
                    (flags & dev.krypt04mcg.crypto.CryptoService.FLAG_SIGNED) == 0 ? "NONE" : algorithms.signature(),
                    algorithms.aead(), algorithms.hkdf());
            if ((flags & dev.krypt04mcg.crypto.CryptoService.FLAG_SIGNED) == 0) {
                signature = new byte[0];
            }
        }
        return new EncryptedPacket(version, type, flags, randomName(random), randomName(random), random.nextLong(),
                randomBytes(random, 16), fragmentIndex, fragmentTotal, algorithms,
                randomBytes(random, random.nextInt(33)), randomBytes(random, random.nextInt(257)),
                randomBytes(random, random.nextInt(513)), signature);
    }

    private static byte[] packetWithOversizedSender(Random random) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        out.writeByte(1);
        out.writeByte(PacketType.KEM_MESSAGE.id());
        out.writeByte(0);
        out.writeShort(4097 + random.nextInt(65535 - 4097));
        return bytes.toByteArray();
    }

    private static byte[] packetWithOversizedKemCiphertext(Random random) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        out.writeByte(1);
        out.writeByte(PacketType.KEM_MESSAGE.id());
        out.writeByte(0);
        writeString(out, "alice");
        writeString(out, "bob");
        out.writeLong(random.nextLong());
        out.write(randomBytes(random, 16));
        out.writeShort(0);
        out.writeShort(1);
        writeString(out, "CMCE/mceliece348864");
        writeString(out, "Falcon-512");
        writeString(out, "AES-256-GCM");
        writeString(out, "HKDF-SHA256");
        out.writeShort(12);
        out.write(randomBytes(random, 12));
        out.writeInt(1024 * 1024 + 1 + random.nextInt(1024));
        return bytes.toByteArray();
    }

    private static void writeString(DataOutputStream out, String value) throws IOException {
        out.writeShort(value.length());
        out.writeBytes(value);
    }

    private static Random random(String testName) {
        long seed = SEED_RANDOM.nextLong();
        System.out.println(PacketCodecFuzzTest.class.getSimpleName() + "." + testName + " seed=" + seed);
        return new Random(seed);
    }

    private static AlgorithmSuite randomAlgorithms(Random random) {
        return new AlgorithmSuite(randomToken(random), randomToken(random), randomToken(random), randomToken(random));
    }

    private static String randomName(Random random) {
        return randomAscii(random, random.nextInt(33));
    }

    private static String randomToken(Random random) {
        return randomAscii(random, 1 + random.nextInt(32));
    }

    private static String randomAscii(Random random, int length) {
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append((char) (32 + random.nextInt(95)));
        }
        return builder.toString();
    }

    private static byte[] randomBytes(Random random, int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    private static void assertPacketEquals(EncryptedPacket expected, EncryptedPacket actual) {
        assertEquals(expected.protocolVersion(), actual.protocolVersion());
        assertEquals(expected.type(), actual.type());
        assertEquals(expected.flags(), actual.flags());
        assertEquals(expected.sender(), actual.sender());
        assertEquals(expected.receiver(), actual.receiver());
        assertEquals(expected.timestampMillis(), actual.timestampMillis());
        assertArrayEquals(expected.messageId(), actual.messageId());
        assertEquals(expected.aadFragmentIndex(), actual.aadFragmentIndex());
        assertEquals(expected.aadFragmentTotal(), actual.aadFragmentTotal());
        assertEquals(expected.algorithms(), actual.algorithms());
        assertArrayEquals(expected.nonce(), actual.nonce());
        assertArrayEquals(expected.kemCiphertext(), actual.kemCiphertext());
        assertArrayEquals(expected.ciphertext(), actual.ciphertext());
        assertArrayEquals(expected.signature(), actual.signature());
    }
}
