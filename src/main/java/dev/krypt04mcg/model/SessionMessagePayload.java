package dev.krypt04mcg.model;

public record SessionMessagePayload(int version, String sessionId, long sequence, String message) {
    public static final int VERSION = 1;
}
