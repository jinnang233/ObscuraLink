package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PacketType;
import dev.krypt04mcg.model.PublicIdentity;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.zip.Deflater;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class CryptoServiceTest {
    @Test
    void encryptDecryptAndSignVerify() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid");
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid");

        EncryptedPacket packet = crypto.encryptFor(publicIdentity(bob), alice, "alice", "hello bob", true);
        String plaintext = crypto.decrypt(packet, bob, publicIdentity(alice));

        assertEquals("hello bob", plaintext);
        assertTrue(packet.signed());
    }

    @Test
    void wrongReceiverIsRejected() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid");
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid");
        LocalKeyMaterial charlie = crypto.generateLocalKeys("charlie", "charlie-uuid");

        EncryptedPacket packet = crypto.encryptFor(publicIdentity(bob), alice, "alice", "hello bob", false);

        assertThrows(CryptoException.class, () -> crypto.decrypt(packet, charlie, publicIdentity(alice)));
    }

    @Test
    void modifiedCiphertextIsRejected() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid");
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid");
        EncryptedPacket packet = crypto.encryptFor(publicIdentity(bob), alice, "alice", "hello bob", true);
        byte[] changed = packet.ciphertext().clone();
        changed[0] ^= 0x01;
        EncryptedPacket tampered = new EncryptedPacket(packet.protocolVersion(), packet.type(), packet.flags(),
                packet.sender(), packet.receiver(), packet.timestampMillis(), packet.messageId(),
                packet.aadFragmentIndex(), packet.aadFragmentTotal(), packet.algorithms(), packet.nonce(),
                packet.kemCiphertext(), changed, packet.signature());

        assertThrows(CryptoException.class, () -> crypto.decrypt(tampered, bob, publicIdentity(alice)));
    }

    @Test
    void compressedMessagesRoundTrip() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid");
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid");
        String message = "hello bob ".repeat(80);

        EncryptedPacket packet = crypto.encryptFor(publicIdentity(bob), alice, "alice", message, true, true);
        String plaintext = crypto.decrypt(packet, bob, publicIdentity(alice));

        assertEquals(message, plaintext);
        assertTrue((packet.flags() & CryptoService.FLAG_COMPRESSED) != 0);
    }

    @Test
    void packetAndKeyRecordsSelectMixedPostQuantumParameterSets() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid",
                KemAlgorithm.ML_KEM_512, SignatureAlgorithm.ML_DSA_44);
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid",
                KemAlgorithm.ML_KEM_768, SignatureAlgorithm.FALCON_1024);

        EncryptedPacket packet = crypto.encryptFor(publicIdentity(bob), alice, "alice", "mixed suite", true,
                false, AeadAlgorithm.CHACHA20_POLY1305);

        assertEquals("ML-KEM-768", packet.algorithms().kem());
        assertEquals("ML-DSA-44", packet.algorithms().signature());
        assertEquals("ChaCha20-Poly1305", packet.algorithms().aead());
        assertEquals("mixed suite", crypto.decrypt(packet, bob, publicIdentity(alice)));
    }

    @Test
    void compressedEmptyMessageRoundTrips() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid");
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid");

        EncryptedPacket packet = crypto.encryptFor(publicIdentity(bob), alice, "alice", "", true, true);
        String plaintext = crypto.decrypt(packet, bob, publicIdentity(alice));

        assertEquals("", plaintext);
        assertTrue((packet.flags() & CryptoService.FLAG_COMPRESSED) != 0);
    }

    @Test
    void sessionMessagesUseSessionSecret() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid");
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid");
        byte[] sessionSecret = new byte[32];
        new SecureRandom().nextBytes(sessionSecret);

        EncryptedPacket packet = crypto.encryptWithSession("bob", alice, "alice", sessionSecret,
                "hello over session", true, true);
        String plaintext = crypto.decryptWithSession(packet, bob, publicIdentity(alice), sessionSecret);

        assertEquals(PacketType.SESSION_MESSAGE, packet.type());
        assertEquals(0, packet.kemCiphertext().length);
        assertEquals("hello over session", plaintext);
        assertTrue(packet.ciphertext().length > 0);
    }

    @Test
    void sessionMessageWithWrongSecretIsRejected() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid");
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid");
        byte[] sessionSecret = new byte[32];
        byte[] wrongSecret = new byte[32];
        new SecureRandom().nextBytes(sessionSecret);
        new SecureRandom().nextBytes(wrongSecret);

        EncryptedPacket packet = crypto.encryptWithSession("bob", alice, "alice", sessionSecret,
                "hello over session", true, false);

        assertThrows(CryptoException.class, () ->
                crypto.decryptWithSession(packet, bob, publicIdentity(alice), wrongSecret));
    }

    @Test
    void oversizedPlaintextEncryptionIsRejected() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid");
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid");
        String message = "A".repeat(CryptoService.MAX_PLAINTEXT_BYTES + 1);

        assertThrows(CryptoException.class, () ->
                crypto.encryptFor(publicIdentity(bob), alice, "alice", message, true, true));
    }

    @Test
    void oversizedCompressedPayloadInflationIsRejected() throws Exception {
        Method inflate = CryptoService.class.getDeclaredMethod("inflate", byte[].class);
        inflate.setAccessible(true);
        byte[] compressed = deflate("A".repeat(CryptoService.MAX_PLAINTEXT_BYTES + 1).getBytes());

        InvocationTargetException exception = assertThrows(InvocationTargetException.class, () ->
                inflate.invoke(null, (Object) compressed));

        assertTrue(exception.getCause() instanceof CryptoException);
    }

    private static PublicIdentity publicIdentity(LocalKeyMaterial material) {
        return new PublicIdentity(material.kemPublicKey().owner(), material.kemPublicKey().uuid(),
                material.kemPublicKey(), material.signaturePublicKey());
    }

    private static byte[] deflate(byte[] plaintext) {
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        deflater.setInput(plaintext);
        deflater.finish();
        byte[] buffer = new byte[512];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            out.write(buffer, 0, count);
        }
        deflater.end();
        return out.toByteArray();
    }
}
