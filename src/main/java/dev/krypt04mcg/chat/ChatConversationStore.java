package dev.krypt04mcg.chat;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import dev.krypt04mcg.util.JsonSupport;
import dev.krypt04mcg.util.SensitiveFileStore;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BooleanSupplier;

public final class ChatConversationStore {
    private static final int MAX_MESSAGES = 300;
    private static final Type ENTRIES_TYPE = new TypeToken<List<Entry>>() {
    }.getType();

    private final List<Entry> entries = new ArrayList<>();
    private final Gson gson = JsonSupport.prettyGson();
    private final Path historyFile;
    private final BooleanSupplier enabled;
    private final SensitiveFileStore sensitiveFiles;
    private boolean loaded;

    public ChatConversationStore() {
        this.historyFile = null;
        this.enabled = () -> true;
        this.sensitiveFiles = null;
    }

    public ChatConversationStore(Path root) {
        this(root, true);
    }

    public ChatConversationStore(Path root, boolean enabled) {
        this(root, () -> enabled);
    }

    public ChatConversationStore(Path root, BooleanSupplier enabled) {
        this.historyFile = root.resolve("cache").resolve("conversations.json");
        this.enabled = enabled;
        this.sensitiveFiles = new SensitiveFileStore(root);
        load();
    }

    public synchronized void incoming(String player, String message) {
        record(player, message, false, false);
    }

    public synchronized void outgoing(String player, String message) {
        record(player, message, true, false);
    }

    public synchronized void outgoingGroup(String group, String message) {
        record(group, message, true, true);
    }

    public synchronized List<Entry> messagesFor(String player) {
        return messagesForTarget(player, false);
    }

    public synchronized List<Entry> messagesForGroup(String group) {
        return messagesForTarget(group, true);
    }

    public synchronized List<String> peers() {
        return targets(false);
    }

    public synchronized List<String> groups() {
        return targets(true);
    }

    private List<Entry> messagesForTarget(String target, boolean group) {
        return entries.stream()
                .filter(entry -> entry.group() == group)
                .filter(entry -> entry.target().equalsIgnoreCase(target))
                .toList();
    }

    private List<String> targets(boolean group) {
        Set<String> targets = new LinkedHashSet<>();
        entries.stream()
                .filter(entry -> entry.group() == group)
                .sorted(Comparator.comparing(Entry::createdAt))
                .forEach(entry -> targets.add(entry.target()));
        return List.copyOf(targets);
    }

    private void record(String target, String message, boolean outgoing, boolean group) {
        if (!enabled.getAsBoolean()) {
            return;
        }
        load();
        if (target == null || target.isBlank() || message == null || message.isBlank()) {
            return;
        }
        entries.add(new Entry(target.trim(), message, outgoing, Instant.now(), group));
        trim();
        save();
    }

    private void load() {
        if (loaded) {
            return;
        }
        if (historyFile == null || !Files.exists(historyFile)) {
            loaded = enabled.getAsBoolean();
            return;
        }
        try {
            boolean legacyPlaintext = !SensitiveFileStore.isEncrypted(historyFile);
            if (!enabled.getAsBoolean()) {
                if (legacyPlaintext) {
                    sensitiveFiles.writeString(historyFile, Files.readString(historyFile, StandardCharsets.UTF_8));
                }
                return;
            }
            loaded = true;
            List<Entry> loaded = gson.fromJson(sensitiveFiles.readString(historyFile), ENTRIES_TYPE);
            if (loaded != null) {
                loaded.stream()
                        .filter(Entry::isValid)
                        .forEach(entries::add);
                trim();
            }
            if (legacyPlaintext) {
                save();
            }
        } catch (Exception ignored) {
            entries.clear();
        }
    }

    private void save() {
        if (!enabled.getAsBoolean() || historyFile == null) {
            return;
        }
        try {
            sensitiveFiles.writeString(historyFile, gson.toJson(entries, ENTRIES_TYPE));
        } catch (IOException ignored) {
            // Keep the in-memory conversation usable even if the cache file cannot be updated.
        }
    }

    private void trim() {
        while (entries.size() > MAX_MESSAGES) {
            entries.removeFirst();
        }
    }

    public record Entry(String target, String message, boolean outgoing, Instant createdAt, boolean group) {
        private boolean isValid() {
            return target != null && !target.isBlank()
                    && message != null && !message.isBlank()
                    && createdAt != null;
        }
    }
}
