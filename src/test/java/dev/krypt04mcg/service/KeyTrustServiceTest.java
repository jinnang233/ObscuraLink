package dev.krypt04mcg.service;

import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.model.TrustState;
import dev.krypt04mcg.util.SensitiveFileStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class KeyTrustServiceTest {
    @TempDir
    private Path tempDir;

    @Test
    void verificationRequiresAndBindsBothFingerprints() throws Exception {
        CryptoService crypto = new CryptoService();
        PublicIdentity bob = publicIdentity(crypto.generateLocalKeys("bob", "bob-uuid"));
        PublicIdentity replaced = publicIdentity(crypto.generateLocalKeys("bob", "bob-uuid"));
        KeyTrustService trust = new KeyTrustService(tempDir);

        assertFalse(trust.fingerprintMatches(bob, bob.kemPublicKey().fingerprint()));
        assertFalse(trust.fingerprintMatches(bob, bob.signaturePublicKey().fingerprint()));
        assertTrue(trust.fingerprintMatches(bob, KeyTrustService.fingerprintPair(bob)));

        trust.markVerified("bob", bob);
        assertEquals(TrustState.VERIFIED, trust.trustState("bob", bob));
        trust.rememberTofu("bob", bob);
        assertEquals(TrustState.VERIFIED, trust.trustState("bob", bob));
        assertEquals(TrustState.DISTRUSTED, trust.trustState("bob", replaced));
        assertTrue(SensitiveFileStore.isEncrypted(tempDir.resolve("keys").resolve("trust.json")));
    }

    private static PublicIdentity publicIdentity(LocalKeyMaterial material) {
        return new PublicIdentity(material.kemPublicKey().owner(), material.kemPublicKey().uuid(),
                material.kemPublicKey(), material.signaturePublicKey());
    }
}
