package dev.krypt04mcg.config;

import dev.krypt04mcg.util.JsonSupport;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Random;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

final class Krypt04McgConfigFuzzTest {
    private static final SecureRandom SEED_RANDOM = new SecureRandom();
    private static final int CASES = 200;

    @Test
    void randomizedConfigsJsonRoundTrip() {
        Random random = random("randomizedConfigsJsonRoundTrip");

        for (int i = 0; i < CASES; i++) {
            Krypt04McgConfig config = randomConfig(random);

            Krypt04McgConfig decoded = JsonSupport.prettyGson().fromJson(
                    JsonSupport.prettyGson().toJson(config), Krypt04McgConfig.class);

            assertNotNull(decoded);
            assertEquals(config.showProgress, decoded.showProgress);
            assertEquals(config.hideEncryptedRawMessage, decoded.hideEncryptedRawMessage);
            assertEquals(config.verboseMessages, decoded.verboseMessages);
            assertEquals(config.enableCompression, decoded.enableCompression);
            assertEquals(config.showReceiveProgress, decoded.showReceiveProgress);
            assertEquals(config.fragmentSize, decoded.fragmentSize);
            assertEquals(config.sendDelayMs, decoded.sendDelayMs);
            assertEquals(config.sessionTtlMinutes, decoded.sessionTtlMinutes);
            assertEquals(config.maxMessagesPerSession, decoded.maxMessagesPerSession);
            assertEquals(config.rotateAfterBytes, decoded.rotateAfterBytes);
            assertEquals(config.packetPrefix, decoded.packetPrefix);
            assertEquals(config.chatSendMode, decoded.chatSendMode);
            assertEquals(config.serverCommandTemplate, decoded.serverCommandTemplate);
            assertEquals(config.receiveRegexMode, decoded.receiveRegexMode);
            assertEquals(config.receiveRegex, decoded.receiveRegex);
            assertEquals(config.shadowListenMode, decoded.shadowListenMode);
            assertEquals(config.shadowListenRegexes, decoded.shadowListenRegexes);
            assertEquals(config.shadowListenRegex, decoded.shadowListenRegex);
            assertEquals(config.kemAlgorithm, decoded.kemAlgorithm);
            assertEquals(config.signatureAlgorithm, decoded.signatureAlgorithm);
            assertEquals(config.aeadAlgorithm, decoded.aeadAlgorithm);
        }
    }

    @Test
    void randomizedRegexConfigsCompileOrFailCleanly() {
        Random random = random("randomizedRegexConfigsCompileOrFailCleanly");

        for (int i = 0; i < CASES; i++) {
            Krypt04McgConfig config = randomConfig(random);

            compileOrReject(config.receiveRegex);
            for (String shadowListenRegex : config.shadowListenRegexes) {
                compileOrReject(shadowListenRegex);
            }
        }
    }

    private static void compileOrReject(String regex) {
        try {
            Pattern.compile(regex);
        } catch (PatternSyntaxException expected) {
            assertNotNull(expected.getMessage());
        }
    }

    private static Random random(String testName) {
        long seed = SEED_RANDOM.nextLong();
        System.out.println(Krypt04McgConfigFuzzTest.class.getSimpleName() + "." + testName + " seed=" + seed);
        return new Random(seed);
    }

    private static Krypt04McgConfig randomConfig(Random random) {
        Krypt04McgConfig config = new Krypt04McgConfig();
        config.showProgress = random.nextBoolean();
        config.hideEncryptedRawMessage = random.nextBoolean();
        config.verboseMessages = random.nextBoolean();
        config.enableCompression = random.nextBoolean();
        config.showReceiveProgress = random.nextBoolean();
        config.fragmentSize = 1 + random.nextInt(512);
        config.sendDelayMs = random.nextInt(10_000);
        config.sessionTtlMinutes = 1 + random.nextInt(3_000);
        config.maxMessagesPerSession = 1 + random.nextInt(20_000);
        config.rotateAfterBytes = Math.abs(random.nextLong());
        config.packetPrefix = random.nextBoolean() ? "" : randomToken(random);
        config.chatSendMode = ChatSendMode.values()[random.nextInt(ChatSendMode.values().length)];
        config.serverCommandTemplate = random.nextBoolean() ? "/msg <receiver> <fragment>" : randomToken(random);
        config.receiveRegexMode = random.nextBoolean();
        config.receiveRegex = randomRegex(random);
        config.shadowListenMode = random.nextBoolean();
        config.shadowListenRegexes = new java.util.ArrayList<>(java.util.List.of(randomRegex(random), randomRegex(random)));
        config.shadowListenRegex = randomRegex(random);
        config.kemAlgorithm = randomToken(random);
        config.signatureAlgorithm = randomToken(random);
        config.aeadAlgorithm = randomToken(random);
        return config;
    }

    private static String randomRegex(Random random) {
        String[] corpus = {
                "^\\[KRYPT04MCG\\] .+",
                "^<(?<player>[^>]+)>\\s*(?<message>.*)$",
                ".*",
                "[",
                "(?<player>.+",
                randomToken(random)
        };
        return corpus[random.nextInt(corpus.length)];
    }

    private static String randomToken(Random random) {
        int length = 1 + random.nextInt(32);
        StringBuilder builder = new StringBuilder(length);
        String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_+.-[](){}?*^$ ";
        for (int i = 0; i < length; i++) {
            builder.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        return builder.toString();
    }
}
