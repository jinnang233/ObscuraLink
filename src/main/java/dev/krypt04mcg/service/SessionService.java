package dev.krypt04mcg.service;

import com.google.gson.Gson;
import dev.krypt04mcg.model.SessionRecord;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.JsonSupport;
import dev.krypt04mcg.util.SensitiveFileStore;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Arrays;

public final class SessionService {
    private final Path sessionsDir;
    private final SecureRandom random = new SecureRandom();
    private final Gson gson = JsonSupport.prettyGson();
    private final SensitiveFileStore sensitiveFiles;

    public SessionService(Path root) {
        this.sessionsDir = root.resolve("sessions");
        this.sensitiveFiles = new SensitiveFileStore(root);
    }

    public synchronized void migrateLegacyFiles() throws IOException {
        if (!Files.isDirectory(sessionsDir)) {
            return;
        }
        try (var stream = Files.list(sessionsDir)) {
            for (Path path : stream.filter(candidate -> candidate.toString().endsWith(".json")).toList()) {
                if (!SensitiveFileStore.isEncrypted(path)) {
                    SessionRecord record = read(path);
                    validate(record);
                    save(record);
                }
            }
        }
    }

    public SessionRecord createLocalSession(String peer, String peerFingerprint) throws IOException {
        SessionRecord record = newSession(peer, peerFingerprint);
        save(record);
        return record;
    }

    public SessionRecord newSession(String peer, String peerFingerprint) {
        byte[] id = new byte[16];
        random.nextBytes(id);
        try {
            return newSession(peer, peerFingerprint, Base64Url.encode(id));
        } finally {
            Arrays.fill(id, (byte) 0);
        }
    }

    public SessionRecord newSession(String peer, String peerFingerprint, String sessionId) {
        byte[] secret = new byte[32];
        random.nextBytes(secret);
        try {
            return new SessionRecord(peer, peerFingerprint, sessionId, Instant.now(), Instant.now(),
                    Base64Url.encode(secret), 0, 0L, 0L, 0L);
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    public SessionRecord acceptRemoteSession(String peer, String peerFingerprint, String sessionId, String secret)
            throws IOException {
        SessionRecord record = new SessionRecord(peer, peerFingerprint, sessionId, Instant.now(), Instant.now(),
                secret, 0, 0L, 0L, 0L);
        save(record);
        return record;
    }

    public Optional<SessionRecord> find(String peer) throws IOException {
        Path path = pathFor(peer);
        if (!Files.exists(path)) {
            return Optional.empty();
        }
        SessionRecord record = read(path);
        validate(record);
        if (!SensitiveFileStore.isEncrypted(path)) {
            save(record);
        }
        return Optional.of(record);
    }

    public void save(SessionRecord record) throws IOException {
        validate(record);
        sensitiveFiles.writeString(pathFor(record.peer()), gson.toJson(record));
    }

    public List<SessionRecord> list() throws IOException {
        if (!Files.exists(sessionsDir)) {
            return List.of();
        }
        try (var stream = Files.list(sessionsDir)) {
            return stream.filter(path -> path.toString().endsWith(".json"))
                    .map(path -> {
                        try {
                            SessionRecord record = read(path);
                            validate(record);
                            if (!SensitiveFileStore.isEncrypted(path)) {
                                save(record);
                            }
                            return record;
                        } catch (IOException e) {
                            throw new IllegalStateException("Unable to read session " + path, e);
                        }
                    })
                    .toList();
        } catch (IllegalStateException e) {
            if (e.getCause() instanceof IOException ioException) {
                throw ioException;
            }
            throw e;
        }
    }

    public void clear(String peer) throws IOException {
        Files.deleteIfExists(pathFor(peer));
    }

    public synchronized void recordSentMessage(String peer, long expectedSequence, long bytes) throws IOException {
        SessionRecord session = find(peer)
                .orElseThrow(() -> new IOException("No active session for " + peer));
        if (session.nextSendSequence() != expectedSequence) {
            throw new IOException("Session send sequence changed for " + peer);
        }
        save(new SessionRecord(session.peer(), session.peerFingerprint(), session.sessionId(), session.createdAt(),
                Instant.now(), session.secret(), session.messageCount() + 1, session.bytesUsed() + Math.max(0, bytes),
                expectedSequence + 1, session.nextReceiveSequence()));
    }

    public synchronized void recordReceivedMessage(String peer, String sessionId, long sequence, long bytes)
            throws IOException {
        SessionRecord session = find(peer)
                .orElseThrow(() -> new IOException("No active session for " + peer));
        if (!session.sessionId().equals(sessionId) || session.nextReceiveSequence() != sequence) {
            throw new IOException("Session epoch or receive sequence mismatch for " + peer);
        }
        save(new SessionRecord(session.peer(), session.peerFingerprint(), session.sessionId(), session.createdAt(),
                Instant.now(), session.secret(), session.messageCount() + 1, session.bytesUsed() + Math.max(0, bytes),
                session.nextSendSequence(), sequence + 1));
    }

    public boolean isExpired(SessionRecord session, int ttlMinutes, int maxMessages, long rotateAfterBytes) {
        Instant expiresAt = session.createdAt().plus(Duration.ofMinutes(ttlMinutes));
        return Instant.now().isAfter(expiresAt)
                || session.messageCount() >= maxMessages
                || session.bytesUsed() >= rotateAfterBytes;
    }

    private Path pathFor(String peer) {
        return sessionsDir.resolve(peer.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9_.-]", "_") + ".json");
    }

    private SessionRecord read(Path path) throws IOException {
        return gson.fromJson(sensitiveFiles.readString(path), SessionRecord.class);
    }

    private static void validate(SessionRecord record) throws IOException {
        try {
            if (record == null || record.peer() == null || record.peer().isBlank()
                    || record.peerFingerprint() == null || record.peerFingerprint().isBlank()
                    || record.createdAt() == null || record.lastUsedAt() == null
                    || Base64Url.decode(record.sessionId()).length != 16
                    || Base64Url.decode(record.secret()).length != 32
                    || record.messageCount() < 0 || record.bytesUsed() < 0
                    || record.nextSendSequence() < 0 || record.nextReceiveSequence() < 0) {
                throw new IOException("Session record is invalid");
            }
        } catch (IllegalArgumentException e) {
            throw new IOException("Session record contains invalid key material", e);
        }
    }
}
