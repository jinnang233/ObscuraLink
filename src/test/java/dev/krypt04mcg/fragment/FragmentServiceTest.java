package dev.krypt04mcg.fragment;

import dev.krypt04mcg.model.Fragment;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class FragmentServiceTest {
    @Test
    void reassemblesOutOfOrderAndIgnoresDuplicate() {
        FragmentService service = new FragmentService();
        FragmentReassembler reassembler = new FragmentReassembler();
        byte[] packet = new byte[300];
        for (int i = 0; i < packet.length; i++) {
            packet[i] = (byte) i;
        }
        List<String> lines = service.fragment(packet, fixedId(), 96);

        Fragment second = service.parse(lines.get(1));
        Fragment first = service.parse(lines.get(0));
        assertTrue(reassembler.accept(second).isEmpty());
        assertTrue(reassembler.accept(second).isEmpty());
        Optional<byte[]> result = Optional.empty();
        for (int i = 0; i < lines.size(); i++) {
            result = reassembler.accept(service.parse(lines.get(i)));
        }

        assertTrue(result.isPresent());
        assertArrayEquals(packet, result.get());
    }

    @Test
    void capsFragmentsToMinecraftChatLimit() {
        FragmentService service = new FragmentService();
        byte[] packet = new byte[3000];
        for (int i = 0; i < packet.length; i++) {
            packet[i] = (byte) i;
        }

        List<String> lines = service.fragment(packet, fixedId(), 680);

        assertTrue(lines.size() > 1);
        for (String line : lines) {
            assertTrue(line.length() <= FragmentService.MAX_CHAT_MESSAGE_LENGTH,
                    "fragment length was " + line.length());
        }
    }

    @Test
    void supportsCustomPrefix() {
        FragmentService service = new FragmentService();
        byte[] packet = new byte[]{1, 2, 3};

        List<String> lines = service.fragment(packet, fixedId(), 96, "[CUSTOM]");

        assertTrue(lines.getFirst().startsWith("[CUSTOM] "));
        assertTrue(service.isFragment(lines.getFirst(), "[CUSTOM]"));
        assertEquals(0, service.parse(lines.getFirst(), "[CUSTOM]").index());
    }

    @Test
    void supportsEmptyPrefix() {
        FragmentService service = new FragmentService();
        byte[] packet = new byte[]{1, 2, 3};

        List<String> lines = service.fragment(packet, fixedId(), 96, "");

        assertTrue(lines.getFirst().startsWith("00000000000000000000000000000000 0 1 "));
        assertTrue(service.isFragment(lines.getFirst(), ""));
        assertEquals(1, service.parse(lines.getFirst(), "").total());
    }

    @Test
    void cleanupRemovesTimedOutMessages() {
        MutableClock clock = new MutableClock();
        FragmentReassembler reassembler = new FragmentReassembler(clock, Duration.ofSeconds(1), 10, 10);
        Fragment fragment = new Fragment("abc", 0, 2, "aaa");
        assertTrue(reassembler.accept(fragment).isEmpty());
        assertEquals(1, reassembler.pendingMessages());
        clock.advance(Duration.ofSeconds(2));
        assertEquals(1, reassembler.cleanup());
        assertEquals(0, reassembler.pendingMessages());
    }

    private static byte[] fixedId() {
        return new byte[16];
    }

    private static final class MutableClock extends Clock {
        private Instant now = Instant.EPOCH;

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
