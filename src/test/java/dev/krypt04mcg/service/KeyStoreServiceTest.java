package dev.krypt04mcg.service;

import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.crypto.CryptoException;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.util.JsonSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class KeyStoreServiceTest {
    @TempDir
    private Path tempDir;

    @Test
    void generatesAndReloadsLocalKeys() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService first = new KeyStoreService(tempDir, cryptoService);
        first.init("alice", "alice-uuid");

        Path localKeys = tempDir.resolve("keys").resolve("private").resolve("local.json");
        Path publicKeys = tempDir.resolve("keys").resolve("public").resolve("self-public.json");
        Path exportedPublicKeys = tempDir.resolve("export").resolve("self-public.json");
        assertTrue(Files.exists(localKeys));
        assertTrue(Files.exists(publicKeys));
        assertTrue(Files.exists(exportedPublicKeys));

        KeyStoreService second = new KeyStoreService(tempDir, cryptoService);
        second.init("alice", "alice-uuid");

        assertEquals(first.local().kemPublicKey().fingerprint(), second.local().kemPublicKey().fingerprint());
        assertEquals(first.local().signaturePublicKey().fingerprint(), second.local().signaturePublicKey().fingerprint());
    }

    @Test
    void configChangesDoNotReplaceExistingKeysUntilFingerprintConfirmedRegeneration() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService first = new KeyStoreService(tempDir, cryptoService);
        first.init("alice", "alice-uuid");
        String originalFingerprint = first.regenerationFingerprint();

        KeyStoreService reloaded = new KeyStoreService(tempDir, cryptoService);
        reloaded.init("alice", "alice-uuid", KemAlgorithm.ML_KEM_512, SignatureAlgorithm.ML_DSA_44);

        assertEquals(originalFingerprint, reloaded.regenerationFingerprint());
        assertEquals("CMCE/mceliece348864/public", reloaded.local().kemPublicKey().algorithm());
        assertEquals("Falcon-512/public", reloaded.local().signaturePublicKey().algorithm());
        assertThrows(CryptoException.class, () -> reloaded.regenerate("wrong-fingerprint",
                KemAlgorithm.ML_KEM_512, SignatureAlgorithm.ML_DSA_44));

        LocalKeyMaterial regenerated = reloaded.regenerate(originalFingerprint,
                KemAlgorithm.ML_KEM_512, SignatureAlgorithm.ML_DSA_44);

        assertNotEquals(originalFingerprint, regenerated.kemPublicKey().fingerprint());
        assertEquals("ML-KEM-512/public", regenerated.kemPublicKey().algorithm());
        assertEquals("ML-DSA-44/public", regenerated.signaturePublicKey().algorithm());

        KeyStoreService afterRestart = new KeyStoreService(tempDir, cryptoService);
        afterRestart.init("alice", "alice-uuid");
        assertEquals(regenerated.kemPublicKey().fingerprint(), afterRestart.local().kemPublicKey().fingerprint());
        assertEquals("ML-KEM-512/public", afterRestart.local().kemPublicKey().algorithm());
    }

    @Test
    void exportsPublicIdentityToExportDirectory() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService keyStoreService = new KeyStoreService(tempDir, cryptoService);
        keyStoreService.init("alice", "alice-uuid");

        KeyStoreService.PublicKeyExport exported = keyStoreService.exportOwnPublicFile();

        assertEquals(tempDir.resolve("export").resolve("self-public.json").toAbsolutePath().normalize(), exported.path());
        assertTrue(Files.exists(exported.path()));
        PublicIdentity exportedIdentity = JsonSupport.prettyGson()
                .fromJson(Files.readString(exported.path()), PublicIdentity.class);
        assertEquals(keyStoreService.local().kemPublicKey().fingerprint(),
                exportedIdentity.kemPublicKey().fingerprint());
        assertEquals(keyStoreService.local().signaturePublicKey().fingerprint(),
                exportedIdentity.signaturePublicKey().fingerprint());
        assertEquals(exportedIdentity.kemPublicKey().fingerprint(), exported.identity().kemPublicKey().fingerprint());
    }

    @Test
    void findsPublicIdentityByOwnerWhenFilenameDiffers() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService keyStoreService = new KeyStoreService(tempDir, cryptoService);
        keyStoreService.init("alice", "alice-uuid");
        LocalKeyMaterial peerKeys = cryptoService.generateLocalKeys("casey", "casey-uuid");
        PublicIdentity peer = publicIdentity(peerKeys);

        Path publicDir = tempDir.resolve("keys").resolve("public");
        Files.writeString(publicDir.resolve("casey-public.json"), JsonSupport.prettyGson().toJson(peer));

        PublicIdentity found = keyStoreService.findPublicIdentity("casey").orElseThrow();
        assertEquals(peer.kemPublicKey().fingerprint(), found.kemPublicKey().fingerprint());
    }

    @Test
    void importsPublicIdentityFromConfigRelativeFile() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService keyStoreService = new KeyStoreService(tempDir, cryptoService);
        keyStoreService.init("alice", "alice-uuid");
        LocalKeyMaterial peerKeys = cryptoService.generateLocalKeys("casey", "casey-uuid");
        PublicIdentity peer = publicIdentity(peerKeys);

        Files.writeString(tempDir.resolve("casey.json"), JsonSupport.prettyGson().toJson(peer));
        keyStoreService.importPublicIdentity("casey", "casey.json");

        PublicIdentity found = keyStoreService.findPublicIdentity("casey").orElseThrow();
        assertEquals(peer.signaturePublicKey().fingerprint(), found.signaturePublicKey().fingerprint());
    }

    @Test
    void importsPublicIdentityFromQuotedConfigRelativeFile() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService keyStoreService = new KeyStoreService(tempDir, cryptoService);
        keyStoreService.init("alice", "alice-uuid");
        LocalKeyMaterial peerKeys = cryptoService.generateLocalKeys("casey", "casey-uuid");
        PublicIdentity peer = publicIdentity(peerKeys);

        Files.writeString(tempDir.resolve("casey quoted.json"), JsonSupport.prettyGson().toJson(peer));
        keyStoreService.importPublicIdentity("casey", "\"casey quoted.json\"");

        PublicIdentity found = keyStoreService.findPublicIdentity("casey").orElseThrow();
        assertEquals(peer.signaturePublicKey().fingerprint(), found.signaturePublicKey().fingerprint());
    }

    @Test
    void rejectsConfigRelativeImportPathTraversal() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService keyStoreService = new KeyStoreService(tempDir, cryptoService);
        keyStoreService.init("alice", "alice-uuid");
        Path outside = Files.createTempFile("krypt04mcg-outside-", ".json");
        try {
            Files.writeString(outside, "{}");
            String traversal = tempDir.relativize(outside).toString();

            assertThrows(Exception.class, () -> keyStoreService.importPublicIdentity("casey", traversal));
        } finally {
            Files.deleteIfExists(outside);
        }
    }

    private static PublicIdentity publicIdentity(LocalKeyMaterial material) {
        return new PublicIdentity(material.kemPublicKey().owner(), material.kemPublicKey().uuid(),
                material.kemPublicKey(), material.signaturePublicKey());
    }
}
