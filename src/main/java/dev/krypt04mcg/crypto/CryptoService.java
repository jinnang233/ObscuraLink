package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.model.AlgorithmSuite;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.KeyRecord;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PacketType;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.Hex;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public final class CryptoService {
    public static final int MESSAGE_ID_BYTES = 16;
    public static final byte FLAG_SIGNED = 0x01;
    public static final byte FLAG_COMPRESSED = 0x02;
    public static final int MAX_PLAINTEXT_BYTES = 64 * 1024;
    private static final int NONCE_BYTES = 12;
    private static final int AEAD_KEY_BYTES = 32;
    private static final int GCM_TAG_BITS = 128;
    private static final String BCPQC = "BCPQC";
    private static final String BC = "BC";

    private final SecureRandom secureRandom;
    private final PacketCodec packetCodec;

    public CryptoService() {
        this(new SecureRandom(), new PacketCodec());
    }

    public CryptoService(SecureRandom secureRandom, PacketCodec packetCodec) {
        ensureProviders();
        this.secureRandom = secureRandom;
        this.packetCodec = packetCodec;
    }

    public LocalKeyMaterial generateLocalKeys(String owner, String uuid) throws CryptoException {
        return generateLocalKeys(owner, uuid, KemAlgorithm.CMCE_MCELIECE348864, SignatureAlgorithm.FALCON_512);
    }

    public LocalKeyMaterial generateLocalKeys(String owner, String uuid, KemAlgorithm kemAlgorithm,
                                              SignatureAlgorithm signatureAlgorithm) throws CryptoException {
        KemAlgorithm selectedKem = kemAlgorithm == null ? KemAlgorithm.CMCE_MCELIECE348864 : kemAlgorithm;
        SignatureAlgorithm selectedSignature = signatureAlgorithm == null
                ? SignatureAlgorithm.FALCON_512 : signatureAlgorithm;
        try {
            KeyPairGenerator kemGenerator = KeyPairGenerator.getInstance(selectedKem.jcaName(), selectedKem.provider());
            kemGenerator.initialize(selectedKem.parameterSpec(), secureRandom);
            KeyPair kem = kemGenerator.generateKeyPair();

            KeyPairGenerator sigGenerator = KeyPairGenerator.getInstance(
                    selectedSignature.jcaName(), selectedSignature.provider());
            sigGenerator.initialize(selectedSignature.parameterSpec(), secureRandom);
            KeyPair sig = sigGenerator.generateKeyPair();

            Instant now = Instant.now();
            return new LocalKeyMaterial(
                    keyRecord(selectedKem.identifier() + "/public", owner, uuid, now, kem.getPublic().getEncoded()),
                    keyRecord(selectedKem.identifier() + "/private", owner, uuid, now, kem.getPrivate().getEncoded()),
                    keyRecord(selectedSignature.identifier() + "/public", owner, uuid, now, sig.getPublic().getEncoded()),
                    keyRecord(selectedSignature.identifier() + "/private", owner, uuid, now, sig.getPrivate().getEncoded())
            );
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Unable to generate post-quantum keys", e);
        }
    }

    public byte[] randomMessageId() {
        byte[] id = new byte[MESSAGE_ID_BYTES];
        secureRandom.nextBytes(id);
        return id;
    }

    public EncryptedPacket encryptFor(PublicIdentity receiver, LocalKeyMaterial senderKeys, String sender, String message, boolean sign)
            throws CryptoException {
        return encryptFor(receiver, senderKeys, sender, message, sign, false);
    }

    public EncryptedPacket encryptFor(PublicIdentity receiver, LocalKeyMaterial senderKeys, String sender, String message,
                                      boolean sign, boolean compress)
            throws CryptoException {
        return encryptFor(receiver, senderKeys, sender, message, sign, compress, AeadAlgorithm.AES_256_GCM);
    }

    public EncryptedPacket encryptFor(PublicIdentity receiver, LocalKeyMaterial senderKeys, String sender, String message,
                                      boolean sign, boolean compress, AeadAlgorithm aeadAlgorithm)
            throws CryptoException {
        KemAlgorithm kemAlgorithm = kemAlgorithm(receiver.kemPublicKey());
        SignatureAlgorithm signatureAlgorithm = signatureAlgorithm(senderKeys.signaturePrivateKey());
        AeadAlgorithm selectedAead = aeadAlgorithm == null ? AeadAlgorithm.AES_256_GCM : aeadAlgorithm;
        try {
            byte[] messageId = randomMessageId();
            PublicKey kemPublic = decodePublicKey(kemAlgorithm.jcaName(), kemAlgorithm.provider(),
                    receiver.kemPublicKey().keyData());
            KeyGenerator keyGenerator = KeyGenerator.getInstance(kemAlgorithm.jcaName(), kemAlgorithm.provider());
            keyGenerator.init(new KEMGenerateSpec.Builder(kemPublic, "AES", AEAD_KEY_BYTES * 8)
                    .withNoKdf().build(), secureRandom);
            SecretKeyWithEncapsulation kemSecret = (SecretKeyWithEncapsulation) keyGenerator.generateKey();
            byte[] encapsulation = kemSecret.getEncapsulation();
            byte[] derivedKey = hkdf(kemSecret.getEncoded(), messageId,
                    "krypt04mcg message aead".getBytes(StandardCharsets.UTF_8), AEAD_KEY_BYTES);
            byte[] nonce = randomNonce();
            byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);
            ensurePlaintextSize(plaintext);
            byte flags = (byte) ((sign ? FLAG_SIGNED : 0) | (compress ? FLAG_COMPRESSED : 0));
            byte[] payload = compress ? deflate(plaintext) : plaintext;

            EncryptedPacket packetTemplate = new EncryptedPacket(EncryptedPacket.VERSION,
                    sign ? PacketType.SIGNED_KEM_MESSAGE : PacketType.KEM_MESSAGE,
                    flags, sender, receiver.owner(), System.currentTimeMillis(), messageId,
                    (short) 0, (short) 1, AlgorithmSuite.of(kemAlgorithm, signatureAlgorithm, selectedAead),
                    nonce, encapsulation, new byte[0], new byte[0]);

            byte[] ciphertext = aeadEncrypt(selectedAead, derivedKey, nonce, packetCodec.aadFor(packetTemplate), payload);
            EncryptedPacket unsigned = new EncryptedPacket(packetTemplate.protocolVersion(), packetTemplate.type(), packetTemplate.flags(),
                    packetTemplate.sender(), packetTemplate.receiver(), packetTemplate.timestampMillis(), packetTemplate.messageId(),
                    packetTemplate.aadFragmentIndex(), packetTemplate.aadFragmentTotal(), packetTemplate.algorithms(), nonce,
                    encapsulation, ciphertext, new byte[0]);
            byte[] signature = sign ? sign(senderKeys.signaturePrivateKey(), packetCodec.signatureInput(unsigned)) : new byte[0];
            return new EncryptedPacket(unsigned.protocolVersion(), unsigned.type(), unsigned.flags(), unsigned.sender(),
                    unsigned.receiver(), unsigned.timestampMillis(), unsigned.messageId(), unsigned.aadFragmentIndex(),
                    unsigned.aadFragmentTotal(), unsigned.algorithms(), unsigned.nonce(), unsigned.kemCiphertext(),
                    unsigned.ciphertext(), signature);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new CryptoException("Unable to encrypt message", e);
        }
    }

    public EncryptedPacket encryptWithSession(String receiver, LocalKeyMaterial senderKeys, String sender,
                                              byte[] sessionSecret, String message, boolean sign, boolean compress)
            throws CryptoException {
        return encryptWithSession(receiver, KemAlgorithm.CMCE_MCELIECE348864, senderKeys, sender, sessionSecret,
                message, sign, compress, AeadAlgorithm.AES_256_GCM);
    }

    public EncryptedPacket encryptWithSession(PublicIdentity receiver, LocalKeyMaterial senderKeys, String sender,
                                              byte[] sessionSecret, String message, boolean sign, boolean compress,
                                              AeadAlgorithm aeadAlgorithm) throws CryptoException {
        return encryptWithSession(receiver.owner(), kemAlgorithm(receiver.kemPublicKey()), senderKeys, sender,
                sessionSecret, message, sign, compress, aeadAlgorithm);
    }

    private EncryptedPacket encryptWithSession(String receiver, KemAlgorithm kemAlgorithm,
                                               LocalKeyMaterial senderKeys, String sender, byte[] sessionSecret,
                                               String message, boolean sign, boolean compress,
                                               AeadAlgorithm aeadAlgorithm) throws CryptoException {
        SignatureAlgorithm signatureAlgorithm = signatureAlgorithm(senderKeys.signaturePrivateKey());
        AeadAlgorithm selectedAead = aeadAlgorithm == null ? AeadAlgorithm.AES_256_GCM : aeadAlgorithm;
        try {
            byte[] messageId = randomMessageId();
            byte[] derivedKey = deriveSessionSecret(sessionSecret, messageId);
            byte[] nonce = randomNonce();
            byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);
            ensurePlaintextSize(plaintext);
            byte flags = (byte) ((sign ? FLAG_SIGNED : 0) | (compress ? FLAG_COMPRESSED : 0));
            byte[] payload = compress ? deflate(plaintext) : plaintext;

            EncryptedPacket packetTemplate = new EncryptedPacket(EncryptedPacket.VERSION, PacketType.SESSION_MESSAGE,
                    flags, sender, receiver, System.currentTimeMillis(), messageId, (short) 0, (short) 1,
                    AlgorithmSuite.of(kemAlgorithm, signatureAlgorithm, selectedAead), nonce, new byte[0],
                    new byte[0], new byte[0]);

            byte[] ciphertext = aeadEncrypt(selectedAead, derivedKey, nonce, packetCodec.aadFor(packetTemplate), payload);
            EncryptedPacket unsigned = new EncryptedPacket(packetTemplate.protocolVersion(), packetTemplate.type(),
                    packetTemplate.flags(), packetTemplate.sender(), packetTemplate.receiver(),
                    packetTemplate.timestampMillis(), packetTemplate.messageId(), packetTemplate.aadFragmentIndex(),
                    packetTemplate.aadFragmentTotal(), packetTemplate.algorithms(), nonce, new byte[0], ciphertext,
                    new byte[0]);
            byte[] signature = sign ? sign(senderKeys.signaturePrivateKey(), packetCodec.signatureInput(unsigned)) : new byte[0];
            return new EncryptedPacket(unsigned.protocolVersion(), unsigned.type(), unsigned.flags(), unsigned.sender(),
                    unsigned.receiver(), unsigned.timestampMillis(), unsigned.messageId(), unsigned.aadFragmentIndex(),
                    unsigned.aadFragmentTotal(), unsigned.algorithms(), unsigned.nonce(), unsigned.kemCiphertext(),
                    unsigned.ciphertext(), signature);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new CryptoException("Unable to encrypt session message", e);
        }
    }

    public String decrypt(EncryptedPacket packet, LocalKeyMaterial receiverKeys, PublicIdentity claimedSender)
            throws CryptoException {
        validateProtocol(packet);
        if (!packet.receiver().equalsIgnoreCase(receiverKeys.kemPublicKey().owner())) {
            throw new CryptoException("Packet receiver mismatch: expected " + receiverKeys.kemPublicKey().owner() + ", got " + packet.receiver());
        }
        KemAlgorithm packetKem = kemAlgorithm(packet.algorithms().kem());
        requireSameAlgorithm("KEM", packetKem.identifier(), kemAlgorithm(receiverKeys.kemPrivateKey()).identifier());
        SignatureAlgorithm packetSignature = signatureAlgorithm(packet.algorithms().signature());
        AeadAlgorithm packetAead = aeadAlgorithm(packet.algorithms().aead());
        validateHkdf(packet.algorithms().hkdf());
        try {
            PrivateKey privateKey = decodePrivateKey(packetKem.jcaName(), packetKem.provider(),
                    receiverKeys.kemPrivateKey().keyData());
            KeyGenerator keyGenerator = KeyGenerator.getInstance(packetKem.jcaName(), packetKem.provider());
            keyGenerator.init(new KEMExtractSpec.Builder(privateKey, packet.kemCiphertext(), "AES",
                    AEAD_KEY_BYTES * 8).withNoKdf().build());
            SecretKeyWithEncapsulation kemSecret = (SecretKeyWithEncapsulation) keyGenerator.generateKey();
            byte[] derivedKey = hkdf(kemSecret.getEncoded(), packet.messageId(),
                    "krypt04mcg message aead".getBytes(StandardCharsets.UTF_8), AEAD_KEY_BYTES);
            byte[] plaintext = aeadDecrypt(packetAead, derivedKey, packet.nonce(), packetCodec.aadFor(packet),
                    packet.ciphertext());
            if (packet.signed()) {
                requireSameAlgorithm("signature", packetSignature.identifier(),
                        signatureAlgorithm(claimedSender.signaturePublicKey()).identifier());
                EncryptedPacket unsigned = packetCodec.withoutSignature(packet);
                boolean valid = verify(packetSignature, claimedSender.signaturePublicKey(),
                        packetCodec.signatureInput(unsigned), packet.signature());
                if (!valid) {
                    throw new CryptoException("Signature verification failed for " + packet.sender());
                }
            }
            byte[] payload = (packet.flags() & FLAG_COMPRESSED) != 0 ? inflate(plaintext) : plaintext;
            return new String(payload, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new CryptoException("Unable to decrypt message", e);
        }
    }

    public String decryptWithSession(EncryptedPacket packet, LocalKeyMaterial receiverKeys, PublicIdentity claimedSender,
                                     byte[] sessionSecret) throws CryptoException {
        validateProtocol(packet);
        if (!packet.receiver().equalsIgnoreCase(receiverKeys.kemPublicKey().owner())) {
            throw new CryptoException("Packet receiver mismatch: expected " + receiverKeys.kemPublicKey().owner() + ", got " + packet.receiver());
        }
        if (packet.type() != PacketType.SESSION_MESSAGE) {
            throw new CryptoException("Packet is not a session message: " + packet.type());
        }
        kemAlgorithm(packet.algorithms().kem());
        SignatureAlgorithm packetSignature = signatureAlgorithm(packet.algorithms().signature());
        AeadAlgorithm packetAead = aeadAlgorithm(packet.algorithms().aead());
        validateHkdf(packet.algorithms().hkdf());
        try {
            byte[] derivedKey = deriveSessionSecret(sessionSecret, packet.messageId());
            byte[] plaintext = aeadDecrypt(packetAead, derivedKey, packet.nonce(), packetCodec.aadFor(packet),
                    packet.ciphertext());
            if (packet.signed()) {
                requireSameAlgorithm("signature", packetSignature.identifier(),
                        signatureAlgorithm(claimedSender.signaturePublicKey()).identifier());
                EncryptedPacket unsigned = packetCodec.withoutSignature(packet);
                boolean valid = verify(packetSignature, claimedSender.signaturePublicKey(),
                        packetCodec.signatureInput(unsigned), packet.signature());
                if (!valid) {
                    throw new CryptoException("Signature verification failed for " + packet.sender());
                }
            }
            byte[] payload = (packet.flags() & FLAG_COMPRESSED) != 0 ? inflate(plaintext) : plaintext;
            return new String(payload, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new CryptoException("Unable to decrypt session message", e);
        }
    }

    public byte[] sign(KeyRecord privateKeyRecord, byte[] input) throws CryptoException {
        return sign(signatureAlgorithm(privateKeyRecord), privateKeyRecord, input);
    }

    private byte[] sign(SignatureAlgorithm algorithm, KeyRecord privateKeyRecord, byte[] input)
            throws CryptoException {
        try {
            Signature signature = Signature.getInstance(algorithm.jcaName(), algorithm.provider());
            signature.initSign(decodePrivateKey(algorithm.jcaName(), algorithm.provider(),
                    privateKeyRecord.keyData()), secureRandom);
            signature.update(input);
            return signature.sign();
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new CryptoException("Unable to sign packet", e);
        }
    }

    public boolean verify(KeyRecord publicKeyRecord, byte[] input, byte[] signatureBytes) throws CryptoException {
        return verify(signatureAlgorithm(publicKeyRecord), publicKeyRecord, input, signatureBytes);
    }

    private boolean verify(SignatureAlgorithm algorithm, KeyRecord publicKeyRecord, byte[] input,
                           byte[] signatureBytes) throws CryptoException {
        try {
            Signature signature = Signature.getInstance(algorithm.jcaName(), algorithm.provider());
            signature.initVerify(decodePublicKey(algorithm.jcaName(), algorithm.provider(),
                    publicKeyRecord.keyData()));
            signature.update(input);
            return signature.verify(signatureBytes);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new CryptoException("Unable to verify packet signature", e);
        }
    }

    public byte[] deriveSessionSecret(byte[] secret, byte[] messageId) throws CryptoException {
        return hkdf(secret, messageId, "krypt04mcg session".getBytes(StandardCharsets.UTF_8), AEAD_KEY_BYTES);
    }

    public String fingerprint(byte[] encoded) throws CryptoException {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(encoded);
            return Hex.encode(Arrays.copyOf(digest, 16));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Unable to fingerprint key", e);
        }
    }

    public KeyRecord keyRecord(String algorithm, String owner, String uuid, Instant createdAt, byte[] encoded) throws CryptoException {
        return new KeyRecord(algorithm, owner, uuid, fingerprint(encoded), createdAt, Base64Url.encode(encoded));
    }

    private static void ensureProviders() {
        if (Security.getProvider(BCPQC) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if (Security.getProvider(BC) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private byte[] randomNonce() {
        byte[] nonce = new byte[NONCE_BYTES];
        secureRandom.nextBytes(nonce);
        return nonce;
    }

    private static void ensurePlaintextSize(byte[] plaintext) throws CryptoException {
        if (plaintext.length > MAX_PLAINTEXT_BYTES) {
            throw new CryptoException("Plaintext message is too large: " + plaintext.length);
        }
    }

    private static void validateProtocol(EncryptedPacket packet) throws CryptoException {
        if (packet.protocolVersion() != EncryptedPacket.LEGACY_VERSION
                && packet.protocolVersion() != EncryptedPacket.VERSION) {
            throw new CryptoException("Unsupported protocol version: " + Byte.toUnsignedInt(packet.protocolVersion()));
        }
        if (packet.algorithms() == null) {
            throw new CryptoException("Packet algorithm suite is missing");
        }
    }

    private static KemAlgorithm kemAlgorithm(KeyRecord record) throws CryptoException {
        if (record == null) {
            throw new CryptoException("KEM key record is missing");
        }
        return kemAlgorithm(record.algorithm());
    }

    private static KemAlgorithm kemAlgorithm(String value) throws CryptoException {
        try {
            return KemAlgorithm.fromIdentifier(value);
        } catch (IllegalArgumentException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    private static SignatureAlgorithm signatureAlgorithm(KeyRecord record) throws CryptoException {
        if (record == null) {
            throw new CryptoException("Signature key record is missing");
        }
        return signatureAlgorithm(record.algorithm());
    }

    private static SignatureAlgorithm signatureAlgorithm(String value) throws CryptoException {
        try {
            return SignatureAlgorithm.fromIdentifier(value);
        } catch (IllegalArgumentException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    private static AeadAlgorithm aeadAlgorithm(String value) throws CryptoException {
        try {
            return AeadAlgorithm.fromIdentifier(value);
        } catch (IllegalArgumentException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    private static void validateHkdf(String value) throws CryptoException {
        if (!AlgorithmSuite.HKDF_SHA256.equalsIgnoreCase(value)) {
            throw new CryptoException("Unsupported HKDF algorithm: " + value);
        }
    }

    private static void requireSameAlgorithm(String type, String packetAlgorithm, String keyAlgorithm)
            throws CryptoException {
        if (!packetAlgorithm.equalsIgnoreCase(keyAlgorithm)) {
            throw new CryptoException("Packet " + type + " algorithm " + packetAlgorithm
                    + " does not match key algorithm " + keyAlgorithm);
        }
    }

    private static PublicKey decodePublicKey(String algorithm, String provider, String base64)
            throws GeneralSecurityException {
        return KeyFactory.getInstance(algorithm, provider)
                .generatePublic(new X509EncodedKeySpec(Base64Url.decode(base64)));
    }

    private static PrivateKey decodePrivateKey(String algorithm, String provider, String base64)
            throws GeneralSecurityException {
        return KeyFactory.getInstance(algorithm, provider)
                .generatePrivate(new PKCS8EncodedKeySpec(Base64Url.decode(base64)));
    }

    private static byte[] aeadEncrypt(AeadAlgorithm algorithm, byte[] key, byte[] nonce, byte[] aad,
                                      byte[] plaintext) throws GeneralSecurityException {
        Cipher cipher = aeadCipher(algorithm);
        initAeadCipher(cipher, Cipher.ENCRYPT_MODE, algorithm, key, nonce);
        cipher.updateAAD(aad);
        return cipher.doFinal(plaintext);
    }

    private static byte[] aeadDecrypt(AeadAlgorithm algorithm, byte[] key, byte[] nonce, byte[] aad,
                                      byte[] ciphertext) throws GeneralSecurityException {
        Cipher cipher = aeadCipher(algorithm);
        initAeadCipher(cipher, Cipher.DECRYPT_MODE, algorithm, key, nonce);
        cipher.updateAAD(aad);
        return cipher.doFinal(ciphertext);
    }

    private static Cipher aeadCipher(AeadAlgorithm algorithm) throws GeneralSecurityException {
        return switch (algorithm) {
            case AES_256_GCM -> Cipher.getInstance("AES/GCM/NoPadding");
            case CHACHA20_POLY1305 -> Cipher.getInstance("ChaCha20-Poly1305");
        };
    }

    private static void initAeadCipher(Cipher cipher, int mode, AeadAlgorithm algorithm, byte[] key, byte[] nonce)
            throws GeneralSecurityException {
        switch (algorithm) {
            case AES_256_GCM -> cipher.init(mode, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            case CHACHA20_POLY1305 -> cipher.init(mode, new SecretKeySpec(key, "ChaCha20"),
                    new IvParameterSpec(nonce));
        }
    }

    private static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) throws CryptoException {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt == null || salt.length == 0 ? new byte[32] : salt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);
            byte[] okm = new byte[length];
            byte[] previous = new byte[0];
            int offset = 0;
            int counter = 1;
            while (offset < length) {
                mac.init(new SecretKeySpec(prk, "HmacSHA256"));
                mac.update(previous);
                mac.update(info);
                mac.update((byte) counter);
                previous = mac.doFinal();
                int copy = Math.min(previous.length, length - offset);
                System.arraycopy(previous, 0, okm, offset, copy);
                offset += copy;
                counter++;
            }
            return okm;
        } catch (GeneralSecurityException e) {
            throw new CryptoException("HKDF failed", e);
        }
    }

    private static byte[] deflate(byte[] plaintext) {
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        deflater.setInput(plaintext);
        deflater.finish();
        byte[] buffer = new byte[512];
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            out.write(buffer, 0, count);
        }
        deflater.end();
        return out.toByteArray();
    }

    private static byte[] inflate(byte[] compressed) throws CryptoException {
        Inflater inflater = new Inflater(true);
        inflater.setInput(compressed);
        byte[] buffer = new byte[512];
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        try {
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                if (count > 0) {
                    if (out.size() + count > MAX_PLAINTEXT_BYTES) {
                        throw new CryptoException("Compressed message expands beyond limit");
                    }
                    out.write(buffer, 0, count);
                } else if (!inflater.finished()) {
                    throw new CryptoException("Compressed message is truncated or invalid");
                }
            }
            return out.toByteArray();
        } catch (DataFormatException e) {
            throw new CryptoException("Compressed message is invalid", e);
        } finally {
            inflater.end();
        }
    }
}
