package dev.krypt04mcg.service;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import dev.krypt04mcg.util.Hex;
import dev.krypt04mcg.util.JsonSupport;
import dev.krypt04mcg.util.SecureFiles;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

public final class DecryptionHistoryService {
    private static final Type HISTORY_TYPE = new TypeToken<Map<String, Instant>>() {
    }.getType();
    private static final String PACKET_PREFIX = "packet:";
    private static final String NONCE_PREFIX = "nonce:";
    private static final int MAX_REPLAY_ENTRIES_PER_PLAYER = 32_768;
    private static final Duration REPLAY_RETENTION = Duration.ofMinutes(65);

    private final Path historyFile;
    private final Gson gson = JsonSupport.prettyGson();

    public DecryptionHistoryService(Path root) {
        this.historyFile = root.resolve("cache").resolve("decryption-history.json");
    }

    public synchronized void recordSuccess(String player) throws IOException {
        Map<String, Instant> history = readHistory();
        history.put(normalize(player), Instant.now());
        writeHistory(history);
    }

    public synchronized Optional<Instant> lastSuccess(String player) throws IOException {
        return Optional.ofNullable(readHistory().get(normalize(player)));
    }

    public synchronized boolean recordAcceptedPacket(String player, byte[] messageId, byte[] nonce) throws IOException {
        Map<String, Instant> history = readHistory();
        String normalized = normalize(player);
        String packetKey = PACKET_PREFIX + normalized + ":" + Hex.encode(messageId);
        String nonceKey = NONCE_PREFIX + normalized + ":" + Hex.encode(nonce);
        Instant now = Instant.now();
        pruneExpiredReplayEntries(history, now);
        if (history.containsKey(packetKey) || history.containsKey(nonceKey)) {
            return false;
        }
        String packetPlayerPrefix = PACKET_PREFIX + normalized + ":";
        String noncePlayerPrefix = NONCE_PREFIX + normalized + ":";
        long playerEntries = history.keySet().stream()
                .filter(key -> key.startsWith(packetPlayerPrefix) || key.startsWith(noncePlayerPrefix)).count();
        if (playerEntries > MAX_REPLAY_ENTRIES_PER_PLAYER - 2) {
            return false;
        }
        history.put(packetKey, now);
        history.put(nonceKey, now);
        writeHistory(history);
        return true;
    }

    private Map<String, Instant> readHistory() throws IOException {
        if (!Files.exists(historyFile)) {
            return new HashMap<>();
        }
        Map<String, Instant> history = gson.fromJson(Files.readString(historyFile, StandardCharsets.UTF_8), HISTORY_TYPE);
        return history == null ? new HashMap<>() : new HashMap<>(history);
    }

    private void writeHistory(Map<String, Instant> history) throws IOException {
        SecureFiles.atomicWrite(historyFile, gson.toJson(history, HISTORY_TYPE).getBytes(StandardCharsets.UTF_8));
    }

    private static void pruneExpiredReplayEntries(Map<String, Instant> history, Instant now) {
        Instant cutoff = now.minus(REPLAY_RETENTION);
        history.entrySet().removeIf(entry -> isReplayKey(entry.getKey()) && entry.getValue().isBefore(cutoff));
    }

    private static boolean isReplayKey(String key) {
        return key.startsWith(PACKET_PREFIX) || key.startsWith(NONCE_PREFIX);
    }

    private static String normalize(String player) {
        return player.toLowerCase(Locale.ROOT);
    }
}
