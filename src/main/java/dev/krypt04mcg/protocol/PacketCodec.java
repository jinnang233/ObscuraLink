package dev.krypt04mcg.protocol;

import dev.krypt04mcg.model.AlgorithmSuite;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.PacketType;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class PacketCodec {
    private static final int MAX_STRING_BYTES = 4096;
    private static final int MAX_BYTES32_FIELD_BYTES = 1024 * 1024;

    public byte[] encode(EncryptedPacket packet) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeByte(packet.protocolVersion());
            out.writeByte(packet.type().id());
            out.writeByte(packet.flags());
            writeString(out, packet.sender());
            writeString(out, packet.receiver());
            out.writeLong(packet.timestampMillis());
            writeFixed(out, packet.messageId(), 16, "messageId");
            if (packet.protocolVersion() < EncryptedPacket.VERSION) {
                out.writeShort(packet.aadFragmentIndex());
                out.writeShort(packet.aadFragmentTotal());
            }
            if (packet.protocolVersion() < EncryptedPacket.VERSION || usesKem(packet.type())) {
                writeString(out, packet.algorithms().kem());
            }
            if (packet.protocolVersion() < EncryptedPacket.VERSION || isSigned(packet.flags())) {
                writeString(out, packet.algorithms().signature());
            }
            writeString(out, packet.algorithms().aead());
            writeString(out, packet.algorithms().hkdf());
            writeBytes16(out, packet.nonce());
            writeBytes32(out, packet.kemCiphertext());
            writeBytes32(out, packet.ciphertext());
            writeBytes32(out, packet.signature());
            return bytes.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected packet encoding failure", e);
        }
    }

    public EncryptedPacket decode(byte[] encoded) {
        try {
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(encoded));
            byte version = in.readByte();
            if (version != EncryptedPacket.LEGACY_VERSION && version != EncryptedPacket.PREVIOUS_VERSION
                    && version != EncryptedPacket.VERSION) {
                throw new IOException("Unsupported protocol version: " + Byte.toUnsignedInt(version));
            }
            PacketType type = PacketType.fromId(in.readUnsignedByte());
            byte flags = in.readByte();
            String sender = readString(in);
            String receiver = readString(in);
            long timestamp = in.readLong();
            byte[] messageId = in.readNBytes(16);
            if (messageId.length != 16) {
                throw new IOException("Truncated message id");
            }
            short aadFragmentIndex = 0;
            short aadFragmentTotal = 1;
            if (version < EncryptedPacket.VERSION) {
                aadFragmentIndex = in.readShort();
                aadFragmentTotal = in.readShort();
            }
            String kem = version < EncryptedPacket.VERSION || usesKem(type) ? readString(in) : "NONE";
            String signatureAlgorithm = version < EncryptedPacket.VERSION || isSigned(flags) ? readString(in) : "NONE";
            AlgorithmSuite algorithms = new AlgorithmSuite(kem, signatureAlgorithm, readString(in), readString(in));
            byte[] nonce = readBytes16(in);
            byte[] kemCiphertext = readBytes32(in);
            byte[] ciphertext = readBytes32(in);
            byte[] signature = readBytes32(in);
            if (in.available() != 0) {
                throw new IOException("Trailing packet bytes: " + in.available());
            }
            return new EncryptedPacket(version, type, flags, sender, receiver, timestamp, messageId,
                    aadFragmentIndex, aadFragmentTotal, algorithms, nonce, kemCiphertext, ciphertext, signature);
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid Krypt04Mcg packet", e);
        }
    }

    public byte[] aadFor(EncryptedPacket packet) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeByte(packet.protocolVersion());
            out.writeByte(packet.type().id());
            out.writeByte(packet.flags());
            writeString(out, packet.sender());
            writeString(out, packet.receiver());
            if (packet.protocolVersion() >= EncryptedPacket.VERSION) {
                out.writeLong(packet.timestampMillis());
            }
            writeFixed(out, packet.messageId(), 16, "messageId");
            if (packet.protocolVersion() < EncryptedPacket.VERSION) {
                out.writeShort(packet.aadFragmentIndex());
                out.writeShort(packet.aadFragmentTotal());
            }
            if (packet.protocolVersion() < EncryptedPacket.VERSION || usesKem(packet.type())) {
                writeString(out, packet.algorithms().kem());
            }
            if (packet.protocolVersion() < EncryptedPacket.VERSION || isSigned(packet.flags())) {
                writeString(out, packet.algorithms().signature());
            }
            writeString(out, packet.algorithms().aead());
            if (packet.protocolVersion() >= EncryptedPacket.PREVIOUS_VERSION) {
                writeString(out, packet.algorithms().hkdf());
            }
            return bytes.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected AAD encoding failure", e);
        }
    }

    public byte[] signatureInput(EncryptedPacket packet) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.write(aadFor(packet));
            if (packet.protocolVersion() < EncryptedPacket.VERSION) {
                out.writeLong(packet.timestampMillis());
            }
            writeBytes16(out, packet.nonce());
            writeBytes32(out, packet.kemCiphertext());
            writeBytes32(out, packet.ciphertext());
            return bytes.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected signature input encoding failure", e);
        }
    }

    public EncryptedPacket withoutSignature(EncryptedPacket packet) {
        return new EncryptedPacket(packet.protocolVersion(), packet.type(), packet.flags(), packet.sender(),
                packet.receiver(), packet.timestampMillis(), packet.messageId(), packet.aadFragmentIndex(),
                packet.aadFragmentTotal(), packet.algorithms(), packet.nonce(), packet.kemCiphertext(),
                packet.ciphertext(), new byte[0]);
    }

    private static void writeString(DataOutputStream out, String value) throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        if (encoded.length > 65535) {
            throw new IOException("String too long");
        }
        out.writeShort(encoded.length);
        out.write(encoded);
    }

    private static String readString(DataInputStream in) throws IOException {
        int length = in.readUnsignedShort();
        if (length > MAX_STRING_BYTES) {
            throw new IOException("String field too long: " + length);
        }
        return new String(readExact(in, length, "string"), StandardCharsets.UTF_8);
    }

    private static void writeBytes16(DataOutputStream out, byte[] bytes) throws IOException {
        if (bytes == null) {
            out.writeShort(0);
            return;
        }
        if (bytes.length > 65535) {
            throw new IOException("Field too long for short length");
        }
        out.writeShort(bytes.length);
        out.write(bytes);
    }

    private static byte[] readBytes16(DataInputStream in) throws IOException {
        int length = in.readUnsignedShort();
        return readExact(in, length, "bytes16");
    }

    private static void writeBytes32(DataOutputStream out, byte[] bytes) throws IOException {
        if (bytes == null) {
            out.writeInt(0);
            return;
        }
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private static byte[] readBytes32(DataInputStream in) throws IOException {
        int length = in.readInt();
        if (length < 0) {
            throw new IOException("Negative length");
        }
        if (length > MAX_BYTES32_FIELD_BYTES) {
            throw new IOException("Field too long: " + length);
        }
        return readExact(in, length, "bytes32");
    }

    private static void writeFixed(DataOutputStream out, byte[] bytes, int length, String field) throws IOException {
        if (bytes == null || bytes.length != length) {
            throw new IOException(field + " must be " + length + " bytes, got " + Arrays.toString(bytes));
        }
        out.write(bytes);
    }

    private static byte[] readExact(DataInputStream in, int length, String field) throws IOException {
        byte[] bytes = in.readNBytes(length);
        if (bytes.length != length) {
            throw new IOException("Truncated " + field);
        }
        return bytes;
    }

    private static boolean usesKem(PacketType type) {
        return type != PacketType.SESSION_MESSAGE;
    }

    private static boolean isSigned(byte flags) {
        return (flags & dev.krypt04mcg.crypto.CryptoService.FLAG_SIGNED) != 0;
    }
}
