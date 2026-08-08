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
    public boolean enableConversationHistory = false;
    public boolean showDisclaimerWarning = true;

    @ConfigEntry.BoundedDiscrete(min = 64, max = 200)
    public int fragmentSize = 180;

    @ConfigEntry.BoundedDiscrete(min = 0, max = 5000)
    public int sendDelayMs = 250;

    @ConfigEntry.BoundedDiscrete(min = 5, max = 1440)
    public int sessionTtlMinutes = 60;

    @ConfigEntry.BoundedDiscrete(min = 30, max = 3600)
    public int maxPacketAgeSeconds = 300;

    @ConfigEntry.BoundedDiscrete(min = 0, max = 300)
    public int maxFutureSkewSeconds = 60;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 10000)
    public int maxMessagesPerSession = 100;

    public long rotateAfterBytes = 1024L * 1024L;

    public ChatSendMode chatSendMode = ChatSendMode.CHAT;
    public String serverCommandTemplate = "/msg <receiver> <fragment>";
    public String messagePrefix = "[Krypt04Mcg]";
    public String packetPrefix = "[KRYPT04MCG]";
    public boolean receiveRegexMode = false;
    public String receiveRegex = "^\\[KRYPT04MCG\\] .+";
    public boolean shadowListenMode = false;
    public java.util.List<String> shadowListenRegexes = new java.util.ArrayList<>(
            java.util.List.of("^<(?<player>[^>]+)>\\s*(?<message>.*)$"));
    @ConfigEntry.Gui.Excluded
    public String shadowListenRegex = "^<(?<player>[^>]+)>\\s*(?<message>.*)$";
    public KemAlgorithm kemAlgorithm = KemAlgorithm.CMCE_MCELIECE348864;
    public KemAlgorithm ephemeralKemAlgorithm = KemAlgorithm.ML_KEM_768;
    public SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.FALCON_512;
    public AeadAlgorithm aeadAlgorithm = AeadAlgorithm.AES_256_GCM;

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
        config.showDisclaimerWarning = showDisclaimerWarning;
        config.fragmentSize = fragmentSize;
        config.sendDelayMs = sendDelayMs;
        config.sessionTtlMinutes = sessionTtlMinutes;
        config.maxPacketAgeSeconds = maxPacketAgeSeconds;
        config.maxFutureSkewSeconds = maxFutureSkewSeconds;
        config.maxMessagesPerSession = maxMessagesPerSession;
        config.rotateAfterBytes = rotateAfterBytes;
        config.chatSendMode = chatSendMode;
        config.serverCommandTemplate = serverCommandTemplate;
        config.messagePrefix = messagePrefix;
        config.packetPrefix = packetPrefix;
        config.receiveRegexMode = receiveRegexMode;
        config.receiveRegex = receiveRegex;
        config.shadowListenMode = shadowListenMode;
        config.shadowListenRegexes = new java.util.ArrayList<>(
                shadowListenRegexes == null ? java.util.List.of(shadowListenRegex) : shadowListenRegexes);
        config.shadowListenRegex = shadowListenRegex;
        config.kemAlgorithm = kemAlgorithm == null ? KemAlgorithm.CMCE_MCELIECE348864 : kemAlgorithm;
        config.ephemeralKemAlgorithm = ephemeralKemAlgorithm == null ? KemAlgorithm.ML_KEM_768 : ephemeralKemAlgorithm;
        config.signatureAlgorithm = signatureAlgorithm == null ? SignatureAlgorithm.FALCON_512 : signatureAlgorithm;
        config.aeadAlgorithm = aeadAlgorithm == null ? AeadAlgorithm.AES_256_GCM : aeadAlgorithm;
    }
}
