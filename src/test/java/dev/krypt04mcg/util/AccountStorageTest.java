package dev.krypt04mcg.util;

import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.service.KeyStoreService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class AccountStorageTest {
    @TempDir
    private Path tempDir;

    @Test
    void migratesMatchingLegacyStorageIntoAccountNamespace() throws Exception {
        CryptoService crypto = new CryptoService();
        KeyStoreService legacy = new KeyStoreService(tempDir, crypto);
        legacy.init("alice", "alice-uuid");
        String fingerprint = legacy.regenerationFingerprint();

        Path accountRoot = AccountStorage.resolve(tempDir, "alice", "alice-uuid");

        assertTrue(accountRoot.endsWith(Path.of("accounts", "alice-uuid")));
        assertTrue(Files.exists(accountRoot.resolve("keys").resolve("private").resolve("local.json")));
        assertFalse(Files.exists(tempDir.resolve("keys")));
        KeyStoreService migrated = new KeyStoreService(accountRoot, crypto);
        migrated.init("alice", "alice-uuid");
        assertEquals(fingerprint, migrated.regenerationFingerprint());
    }
}
