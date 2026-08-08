package dev.krypt04mcg.fragment;

import dev.krypt04mcg.model.Fragment;
import dev.krypt04mcg.model.FragmentProgress;
import dev.krypt04mcg.util.Base64Url;

import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class FragmentReassembler {
    public static final int DEFAULT_MAX_FRAGMENTS_PER_MESSAGE = 512;

    private final Clock clock;
    private final Duration timeout;
    private final int maxMessages;
    private final int maxFragmentsPerMessage;
    private final Map<String, PartialMessage> partials = new HashMap<>();

    public FragmentReassembler() {
        this(Clock.systemUTC(), Duration.ofMinutes(2), 128, DEFAULT_MAX_FRAGMENTS_PER_MESSAGE);
    }

    public FragmentReassembler(Clock clock, Duration timeout, int maxMessages, int maxFragmentsPerMessage) {
        this.clock = clock;
        this.timeout = timeout;
        this.maxMessages = maxMessages;
        this.maxFragmentsPerMessage = maxFragmentsPerMessage;
    }

    public synchronized Optional<byte[]> accept(Fragment fragment) {
        cleanupTimedOut();
        if (fragment.total() > maxFragmentsPerMessage) {
            throw new IllegalArgumentException("Too many fragments: " + fragment.total());
        }
        if (partials.size() >= maxMessages && !partials.containsKey(fragment.messageId())) {
            evictOldest();
        }
        PartialMessage partial = partials.computeIfAbsent(fragment.messageId(),
                id -> new PartialMessage(fragment.total(), clock.millis()));
        if (partial.total != fragment.total()) {
            throw new IllegalArgumentException("Fragment total changed for " + fragment.messageId());
        }
        partial.fragments.putIfAbsent(fragment.index(), fragment.payload());
        partial.lastTouched = clock.millis();
        if (!partial.complete()) {
            return Optional.empty();
        }
        StringBuilder payload = new StringBuilder();
        for (int i = 0; i < partial.total; i++) {
            payload.append(partial.fragments.get(i));
        }
        partials.remove(fragment.messageId());
        return Optional.of(Base64Url.decode(payload.toString()));
    }

    public synchronized int cleanup() {
        return cleanupTimedOut().size();
    }

    public synchronized List<FragmentProgress> cleanupTimedOut() {
        long cutoff = clock.millis() - timeout.toMillis();
        List<FragmentProgress> removed = partials.entrySet().stream()
                .filter(entry -> entry.getValue().lastTouched < cutoff)
                .map(entry -> new FragmentProgress(entry.getKey(), entry.getValue().fragments.size(), entry.getValue().total))
                .toList();
        for (FragmentProgress progress : removed) {
            partials.remove(progress.messageId());
        }
        return removed;
    }

    public synchronized Optional<FragmentProgress> progress(String messageId) {
        PartialMessage partial = partials.get(messageId);
        if (partial == null) {
            return Optional.empty();
        }
        return Optional.of(new FragmentProgress(messageId, partial.fragments.size(), partial.total));
    }

    public synchronized int pendingMessages() {
        return partials.size();
    }

    private void evictOldest() {
        String oldestId = null;
        long oldestTime = Long.MAX_VALUE;
        for (Map.Entry<String, PartialMessage> entry : partials.entrySet()) {
            if (entry.getValue().lastTouched < oldestTime) {
                oldestTime = entry.getValue().lastTouched;
                oldestId = entry.getKey();
            }
        }
        if (oldestId != null) {
            partials.remove(oldestId);
        }
    }

    private static final class PartialMessage {
        private final int total;
        private final long createdAt;
        private final Map<Integer, String> fragments = new HashMap<>();
        private long lastTouched;

        private PartialMessage(int total, long now) {
            this.total = total;
            this.createdAt = now;
            this.lastTouched = now;
        }

        private boolean complete() {
            return fragments.size() == total;
        }
    }
}
