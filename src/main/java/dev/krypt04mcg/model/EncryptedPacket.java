package dev.krypt04mcg.model;

public record EncryptedPacket(
        byte protocolVersion,
        PacketType type,
        byte flags,
        String sender,
        String receiver,
        long timestampMillis,
        byte[] messageId,
        short aadFragmentIndex,
        short aadFragmentTotal,
        AlgorithmSuite algorithms,
        byte[] nonce,
        byte[] kemCiphertext,
        byte[] ciphertext,
        byte[] signature
) {
    public static final byte LEGACY_VERSION = 1;
    public static final byte PREVIOUS_VERSION = 2;
    public static final byte VERSION = 3;

    public boolean signed() {
        return signature != null && signature.length > 0;
    }
}
