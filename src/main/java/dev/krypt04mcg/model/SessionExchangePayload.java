package dev.krypt04mcg.model;

public record SessionExchangePayload(
        int version,
        Kind kind,
        String initiator,
        String initiatorUuid,
        String responder,
        String responderUuid,
        String sessionId,
        String requestMessageId,
        String initiatorFingerprint,
        String responderFingerprint,
        String ephemeralKem,
        String ephemeralPublicKey,
        String sessionSecret,
        long createdAtMillis
) {
    public static final int VERSION = 1;

    public enum Kind {
        REQUEST,
        RESPONSE
    }
}
