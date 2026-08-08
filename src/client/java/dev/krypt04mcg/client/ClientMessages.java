package dev.krypt04mcg.client;

import net.minecraft.client.resources.language.I18n;

public final class ClientMessages {
    private static final String DEFAULT_MESSAGE_PREFIX = "[Krypt04Mcg]";
    private static volatile String messagePrefix = DEFAULT_MESSAGE_PREFIX;

    private ClientMessages() {
    }

    public static void setMessagePrefix(String configuredPrefix) {
        messagePrefix = configuredPrefix == null ? DEFAULT_MESSAGE_PREFIX : configuredPrefix;
    }

    public static String messagePrefix() {
        return messagePrefix;
    }

    public static String messagePrefixWithSpace() {
        return messagePrefix.isEmpty() ? "" : messagePrefix + " ";
    }

    public static String tr(String key, Object... args) {
        return applyMessagePrefix(I18n.get(key, args));
    }

    private static String applyMessagePrefix(String message) {
        if (message.startsWith(DEFAULT_MESSAGE_PREFIX)) {
            return messagePrefix + message.substring(DEFAULT_MESSAGE_PREFIX.length());
        }
        return message;
    }
}
