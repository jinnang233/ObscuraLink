package dev.krypt04mcg.util;

import com.sun.jna.Platform;
import com.sun.jna.platform.win32.Crypt32Util;
import com.sun.jna.platform.win32.WinCrypt;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

public final class SensitiveFileStore {
    private static final byte[] FILE_MAGIC = "KMCGSEC1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KEY_MAGIC = "KMCGKEY1".getBytes(StandardCharsets.US_ASCII);
    private static final byte KEY_DPAPI = 1;
    private static final byte KEY_OWNER_ONLY = 2;
    private static final int KEY_BYTES = 32;
    private static final int NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final byte[] DPAPI_ENTROPY = "Krypt04Mcg local storage v1".getBytes(StandardCharsets.UTF_8);

    private final Path root;
    private final Path masterKeyFile;
    private final SecureRandom random = new SecureRandom();
    private byte[] masterKey;

    public SensitiveFileStore(Path root) {
        this.root = root.toAbsolutePath().normalize();
        this.masterKeyFile = this.root.resolve("secrets").resolve("master.key");
    }

    public synchronized String readString(Path path) throws IOException {
        byte[] encoded = Files.readAllBytes(path);
        if (!startsWith(encoded, FILE_MAGIC)) {
            String plaintext = new String(encoded, StandardCharsets.UTF_8);
            Arrays.fill(encoded, (byte) 0);
            return plaintext;
        }
        if (encoded.length < FILE_MAGIC.length + NONCE_BYTES + 16) {
            throw new IOException("Encrypted file is truncated: " + path);
        }
        byte[] nonce = Arrays.copyOfRange(encoded, FILE_MAGIC.length, FILE_MAGIC.length + NONCE_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(encoded, FILE_MAGIC.length + NONCE_BYTES, encoded.length);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(masterKey(), "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(label(path));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IOException("Unable to decrypt sensitive file " + path, e);
        } finally {
            Arrays.fill(nonce, (byte) 0);
            Arrays.fill(ciphertext, (byte) 0);
            Arrays.fill(encoded, (byte) 0);
        }
    }

    public synchronized void writeString(Path path, String value) throws IOException {
        byte[] plaintext = value.getBytes(StandardCharsets.UTF_8);
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(nonce);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(masterKey(), "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(label(path));
            byte[] ciphertext = cipher.doFinal(plaintext);
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(FILE_MAGIC.length + nonce.length + ciphertext.length);
            bytes.write(FILE_MAGIC);
            bytes.write(nonce);
            bytes.write(ciphertext);
            SecureFiles.atomicWrite(path, bytes.toByteArray());
            Arrays.fill(ciphertext, (byte) 0);
        } catch (GeneralSecurityException e) {
            throw new IOException("Unable to encrypt sensitive file " + path, e);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
            Arrays.fill(nonce, (byte) 0);
        }
    }

    public static boolean isEncrypted(Path path) throws IOException {
        if (!Files.isRegularFile(path) || Files.size(path) < FILE_MAGIC.length) {
            return false;
        }
        byte[] prefix = new byte[FILE_MAGIC.length];
        try (var in = Files.newInputStream(path)) {
            return in.read(prefix) == prefix.length && Arrays.equals(prefix, FILE_MAGIC);
        }
    }

    private byte[] masterKey() throws IOException {
        if (masterKey != null) {
            return masterKey;
        }
        if (!Files.exists(masterKeyFile)) {
            byte[] generated = new byte[KEY_BYTES];
            random.nextBytes(generated);
            try {
                writeMasterKey(generated);
                masterKey = generated;
                return masterKey;
            } catch (IOException e) {
                Arrays.fill(generated, (byte) 0);
                throw e;
            }
        }
        byte[] stored = Files.readAllBytes(masterKeyFile);
        try {
            if (!startsWith(stored, KEY_MAGIC) || stored.length <= KEY_MAGIC.length + 1) {
                throw new IOException("Invalid local master key file");
            }
            byte mode = stored[KEY_MAGIC.length];
            byte[] protectedKey = Arrays.copyOfRange(stored, KEY_MAGIC.length + 1, stored.length);
            byte[] unwrapped = switch (mode) {
                case KEY_DPAPI -> unprotectWithDpapi(protectedKey);
                case KEY_OWNER_ONLY -> protectedKey;
                default -> throw new IOException("Unsupported local master key protection mode: " + mode);
            };
            if (unwrapped.length != KEY_BYTES) {
                Arrays.fill(unwrapped, (byte) 0);
                throw new IOException("Invalid local master key length");
            }
            masterKey = unwrapped;
            return masterKey;
        } finally {
            Arrays.fill(stored, (byte) 0);
        }
    }

    private void writeMasterKey(byte[] key) throws IOException {
        byte mode = KEY_OWNER_ONLY;
        byte[] protectedKey = Arrays.copyOf(key, key.length);
        if (Platform.isWindows()) {
            try {
                Arrays.fill(protectedKey, (byte) 0);
                protectedKey = Crypt32Util.cryptProtectData(key, DPAPI_ENTROPY,
                        WinCrypt.CRYPTPROTECT_UI_FORBIDDEN, "Krypt04Mcg local master key", null);
                mode = KEY_DPAPI;
            } catch (RuntimeException | LinkageError e) {
                throw new IOException("Windows DPAPI could not protect the local master key", e);
            }
        }
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.write(KEY_MAGIC);
            out.writeByte(mode);
            out.write(protectedKey);
            SecureFiles.atomicWrite(masterKeyFile, bytes.toByteArray());
        } finally {
            Arrays.fill(protectedKey, (byte) 0);
        }
    }

    private static byte[] unprotectWithDpapi(byte[] protectedKey) throws IOException {
        if (!Platform.isWindows()) {
            throw new IOException("This master key is protected by Windows DPAPI and cannot be opened on this OS");
        }
        try {
            return Crypt32Util.cryptUnprotectData(protectedKey, DPAPI_ENTROPY,
                    WinCrypt.CRYPTPROTECT_UI_FORBIDDEN, null);
        } catch (RuntimeException | LinkageError e) {
            throw new IOException("Windows DPAPI could not unlock the local master key", e);
        }
    }

    private byte[] label(Path path) throws IOException {
        Path normalized = path.toAbsolutePath().normalize();
        if (!normalized.startsWith(root)) {
            throw new IOException("Sensitive file is outside the configured storage root: " + path);
        }
        return root.relativize(normalized).toString().replace('\\', '/').getBytes(StandardCharsets.UTF_8);
    }

    private static boolean startsWith(byte[] value, byte[] prefix) {
        return value.length >= prefix.length
                && ByteBuffer.wrap(value, 0, prefix.length).equals(ByteBuffer.wrap(prefix));
    }
}
