package dev.krypt04mcg.fragment;

import dev.krypt04mcg.model.Fragment;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.Hex;

import java.util.ArrayList;
import java.util.List;

public final class FragmentService {
    public static final String PREFIX = "[KRYPT04MCG]";
    public static final int MAX_CHAT_MESSAGE_LENGTH = 256;
    private static final int MIN_PAYLOAD_SIZE = 32;

    public List<String> fragment(byte[] packetBytes, byte[] messageId, int configuredPayloadSize) {
        return fragment(packetBytes, messageId, configuredPayloadSize, PREFIX);
    }

    public List<String> fragment(byte[] packetBytes, byte[] messageId, int configuredPayloadSize, String prefix) {
        String encoded = Base64Url.encode(packetBytes);
        String id = Hex.encode(messageId);
        String normalizedPrefix = normalizePrefix(prefix);
        int payloadSize = payloadSizeFor(encoded.length(), id, configuredPayloadSize, normalizedPrefix);
        int total = Math.max(1, (int) Math.ceil(encoded.length() / (double) payloadSize));
        List<String> result = new ArrayList<>(total);
        for (int i = 0; i < total; i++) {
            int start = i * payloadSize;
            int end = Math.min(encoded.length(), start + payloadSize);
            String line = headerPrefix(normalizedPrefix) + id + " " + i + " " + total + " " + encoded.substring(start, end);
            if (line.length() > MAX_CHAT_MESSAGE_LENGTH) {
                throw new IllegalStateException("Generated fragment exceeds Minecraft chat limit: " + line.length());
            }
            result.add(line);
        }
        return result;
    }

    public boolean isFragment(String message) {
        return isFragment(message, PREFIX);
    }

    public boolean isFragment(String message, String prefix) {
        if (message == null || message.length() > MAX_CHAT_MESSAGE_LENGTH) {
            return false;
        }
        String normalizedPrefix = normalizePrefix(prefix);
        if (!normalizedPrefix.isEmpty() && !message.startsWith(normalizedPrefix + " ")) {
            return false;
        }
        String[] parts = parts(message, normalizedPrefix);
        if (parts.length != 5) {
            return false;
        }
        try {
            int index = Integer.parseInt(parts[2]);
            int total = Integer.parseInt(parts[3]);
            return index >= 0 && total > 0 && index < total;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public Fragment parse(String message) {
        return parse(message, PREFIX);
    }

    public Fragment parse(String message, String prefix) {
        String normalizedPrefix = normalizePrefix(prefix);
        if (!isFragment(message, normalizedPrefix)) {
            throw new IllegalArgumentException("Not a Krypt04Mcg fragment");
        }
        if (message.length() > MAX_CHAT_MESSAGE_LENGTH) {
            throw new IllegalArgumentException("Krypt04Mcg fragment exceeds Minecraft chat limit");
        }
        String[] parts = parts(message, normalizedPrefix);
        if (parts.length != 5) {
            throw new IllegalArgumentException("Malformed Krypt04Mcg fragment");
        }
        int index = Integer.parseInt(parts[2]);
        int total = Integer.parseInt(parts[3]);
        if (index < 0 || total <= 0 || index >= total) {
            throw new IllegalArgumentException("Invalid fragment index " + index + "/" + total);
        }
        return new Fragment(parts[1], index, total, parts[4]);
    }

    private static int payloadSizeFor(int encodedLength, String id, int configuredPayloadSize, String prefix) {
        int requested = Math.max(MIN_PAYLOAD_SIZE, configuredPayloadSize);
        int payloadSize = Math.min(requested, maxPayloadFor(id, 0, 1, prefix));
        while (true) {
            int total = Math.max(1, (int) Math.ceil(encodedLength / (double) payloadSize));
            int maxPayload = maxPayloadFor(id, total - 1, total, prefix);
            int adjusted = Math.min(requested, maxPayload);
            if (adjusted == payloadSize) {
                return Math.max(MIN_PAYLOAD_SIZE, adjusted);
            }
            payloadSize = Math.max(MIN_PAYLOAD_SIZE, adjusted);
        }
    }

    private static int maxPayloadFor(String id, int index, int total, String prefix) {
        int headerLength = headerPrefix(prefix).length()
                + id.length()
                + 1 + digits(index)
                + 1 + digits(total)
                + 1;
        return MAX_CHAT_MESSAGE_LENGTH - headerLength;
    }

    private static String[] parts(String message, String prefix) {
        if (prefix.isEmpty()) {
            return (" " + message).split(" ", 5);
        }
        return message.split(" ", 5);
    }

    private static String headerPrefix(String prefix) {
        return prefix.isEmpty() ? "" : prefix + " ";
    }

    private static String normalizePrefix(String prefix) {
        return prefix == null ? PREFIX : prefix;
    }

    private static int digits(int value) {
        return Integer.toString(value).length();
    }
}
