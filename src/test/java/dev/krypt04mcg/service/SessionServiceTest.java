package dev.krypt04mcg.service;

import dev.krypt04mcg.model.SessionRecord;
import dev.krypt04mcg.util.SensitiveFileStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SessionServiceTest {
    @TempDir
    private Path tempDir;

    @Test
    void sessionSecretsAreEncryptedAndSequencesAdvanceAtomically() throws Exception {
        SessionService sessions = new SessionService(tempDir);
        SessionRecord created = sessions.createLocalSession("bob", "kem:sig");
        Path file = tempDir.resolve("sessions").resolve("bob.json");

        assertTrue(SensitiveFileStore.isEncrypted(file));
        assertFalse(new String(Files.readAllBytes(file), java.nio.charset.StandardCharsets.ISO_8859_1)
                .contains(created.secret()));

        sessions.recordSentMessage("bob", 0, 5);
        sessions.recordReceivedMessage("bob", created.sessionId(), 0, 7);
        SessionRecord updated = sessions.find("bob").orElseThrow();
        assertEquals(1, updated.nextSendSequence());
        assertEquals(1, updated.nextReceiveSequence());
        assertEquals(2, updated.messageCount());
        assertEquals(12, updated.bytesUsed());
    }
}
