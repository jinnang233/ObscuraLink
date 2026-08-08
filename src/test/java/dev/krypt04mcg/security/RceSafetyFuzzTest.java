package dev.krypt04mcg.security;

import dev.krypt04mcg.fragment.FragmentService;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class RceSafetyFuzzTest {
    private static final SecureRandom SEED_RANDOM = new SecureRandom();
    private static final int CASES = 500;

    @Test
    void randomizedCommandLikePayloadsNeverProduceCommandChatLines() {
        FragmentService fragmentService = new FragmentService();
        Random random = random("randomizedCommandLikePayloadsNeverProduceCommandChatLines");

        for (int i = 0; i < CASES; i++) {
            byte[] packet = randomCommandLikePayload(random).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            List<String> fragments = fragmentService.fragment(packet, randomBytes(random, 16), 1 + random.nextInt(512));

            for (String fragment : fragments) {
                assertFalse(fragment.startsWith("/"), "fragment could be interpreted as a command");
                assertTrue(fragment.startsWith(FragmentService.PREFIX + " "));
            }
        }
    }

    @Test
    void productionSourcesDoNotUseExecutionOrDynamicLoadingApis() throws Exception {
        List<String> forbidden = List.of(
                "Runtime.getRuntime",
                "ProcessBuilder",
                ".exec(",
                "ScriptEngine",
                "ObjectInputStream",
                ".readObject(",
                "Class.forName",
                "URLClassLoader",
                "System.load(",
                "System.loadLibrary("
        );

        for (Path source : productionJavaSources()) {
            String text = Files.readString(source);
            for (String token : forbidden) {
                assertFalse(text.contains(token), source + " contains potential RCE API " + token);
            }
        }
    }

    @Test
    void minecraftChatSenderKeepsFragmentOnlyGuard() throws Exception {
        String modSource = Files.readString(Path.of("src/client/java/dev/krypt04mcg/Krypt04McgMod.java"));

        assertTrue(modSource.contains("fragmentService.isFragment(line, config.packetPrefix)"));
        assertTrue(modSource.contains("sendChat(line)"));
        assertTrue(modSource.contains("sendCommand(formatServerCommand"));
    }

    private static List<Path> productionJavaSources() throws Exception {
        try (var paths = Files.walk(Path.of("src"))) {
            return paths
                    .filter(path -> path.toString().endsWith(".java"))
                    .filter(path -> !path.toString().contains("\\test\\"))
                    .filter(path -> !path.toString().contains("/test/"))
                    .toList();
        }
    }

    private static String randomCommandLikePayload(Random random) {
        String[] prefixes = {
                "/op ",
                "/execute ",
                "/tellraw ",
                "/function ",
                "/plugin:cmd ",
                "&& ",
                "| ",
                "$(",
                "`",
                "powershell -Command ",
                "cmd /c ",
                "bash -c "
        };
        StringBuilder builder = new StringBuilder(prefixes[random.nextInt(prefixes.length)]);
        int length = random.nextInt(256);
        for (int i = 0; i < length; i++) {
            builder.append((char) (32 + random.nextInt(95)));
        }
        return builder.toString();
    }

    private static Random random(String testName) {
        long seed = SEED_RANDOM.nextLong();
        System.out.println(RceSafetyFuzzTest.class.getSimpleName() + "." + testName + " seed=" + seed);
        return new Random(seed);
    }

    private static byte[] randomBytes(Random random, int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
}
