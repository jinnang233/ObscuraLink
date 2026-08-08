package dev.krypt04mcg.config;

public class Krypt04McgConfig {
    public boolean showProgress = true;
    public boolean hideEncryptedRawMessage = true;
    public boolean verboseMessages = false;
    public boolean enableCompression = true;
    public boolean showReceiveProgress = true;
    public boolean enableConversationHistory = true;

    public int fragmentSize = 180;

    public int sendDelayMs = 250;

    public int sessionTtlMinutes = 60;

    public int maxMessagesPerSession = 100;

    public long rotateAfterBytes = 1024L * 1024L;

    public ChatSendMode chatSendMode = ChatSendMode.CHAT;
    public String serverCommandTemplate = "/msg <receiver> <fragment>";
    public String packetPrefix = "[KRYPT04MCG]";
    public boolean receiveRegexMode = false;
    public String receiveRegex = "^\\[KRYPT04MCG\\] .+";
    public boolean shadowListenMode = false;
    public java.util.List<String> shadowListenRegexes = new java.util.ArrayList<>(
            java.util.List.of("^<(?<player>[^>]+)>\\s*(?<message>.*)$"));
    public String shadowListenRegex = "^<(?<player>[^>]+)>\\s*(?<message>.*)$";
    public String kemAlgorithm = "CMCE/mceliece348864";
    public String signatureAlgorithm = "Falcon-512";
    public String aeadAlgorithm = "AES-256-GCM";
}
