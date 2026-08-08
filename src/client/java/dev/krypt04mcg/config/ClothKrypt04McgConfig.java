package dev.krypt04mcg.config;

import me.shedaniel.autoconfig.ConfigData;
import me.shedaniel.autoconfig.annotation.Config;
import me.shedaniel.autoconfig.annotation.ConfigEntry;

@Config(name = "krypt04mcg")
public final class ClothKrypt04McgConfig implements ConfigData {
    public boolean showProgress = true;
    public boolean hideEncryptedRawMessage = true;
    public boolean verboseMessages = false;
    public boolean enableCompression = true;
    public boolean showReceiveProgress = true;
    public boolean enableConversationHistory = true;

    @ConfigEntry.BoundedDiscrete(min = 64, max = 200)
    public int fragmentSize = 180;

    @ConfigEntry.BoundedDiscrete(min = 0, max = 5000)
    public int sendDelayMs = 250;

    @ConfigEntry.BoundedDiscrete(min = 5, max = 1440)
    public int sessionTtlMinutes = 60;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 10000)
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
    @ConfigEntry.Gui.Excluded
    public String shadowListenRegex = "^<(?<player>[^>]+)>\\s*(?<message>.*)$";
    public String kemAlgorithm = "CMCE/mceliece348864";
    public String signatureAlgorithm = "Falcon-512";
    public String aeadAlgorithm = "AES-256-GCM";

    Krypt04McgConfig toCoreConfig() {
        Krypt04McgConfig config = new Krypt04McgConfig();
        copyTo(config);
        return config;
    }

    void copyTo(Krypt04McgConfig config) {
        config.showProgress = showProgress;
        config.hideEncryptedRawMessage = hideEncryptedRawMessage;
        config.verboseMessages = verboseMessages;
        config.enableCompression = enableCompression;
        config.showReceiveProgress = showReceiveProgress;
        config.enableConversationHistory = enableConversationHistory;
        config.fragmentSize = fragmentSize;
        config.sendDelayMs = sendDelayMs;
        config.sessionTtlMinutes = sessionTtlMinutes;
        config.maxMessagesPerSession = maxMessagesPerSession;
        config.rotateAfterBytes = rotateAfterBytes;
        config.chatSendMode = chatSendMode;
        config.serverCommandTemplate = serverCommandTemplate;
        config.packetPrefix = packetPrefix;
        config.receiveRegexMode = receiveRegexMode;
        config.receiveRegex = receiveRegex;
        config.shadowListenMode = shadowListenMode;
        config.shadowListenRegexes = new java.util.ArrayList<>(
                shadowListenRegexes == null ? java.util.List.of(shadowListenRegex) : shadowListenRegexes);
        config.shadowListenRegex = shadowListenRegex;
        config.kemAlgorithm = kemAlgorithm;
        config.signatureAlgorithm = signatureAlgorithm;
        config.aeadAlgorithm = aeadAlgorithm;
    }
}
