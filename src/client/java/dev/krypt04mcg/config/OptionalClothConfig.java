package dev.krypt04mcg.config;

import dev.krypt04mcg.Krypt04McgMod;
import net.fabricmc.loader.api.FabricLoader;

import java.util.function.Consumer;

public final class OptionalClothConfig {
    private static final String CLOTH_CONFIG_MOD_ID = "cloth-config";

    private OptionalClothConfig() {
    }

    public static Krypt04McgConfig loadOrDefault() {
        if (!FabricLoader.getInstance().isModLoaded(CLOTH_CONFIG_MOD_ID)) {
            Krypt04McgMod.LOGGER.info("Cloth Config is not installed; using default Krypt04Mcg settings");
            return new Krypt04McgConfig();
        }
        try {
            return ClothConfigBridge.load();
        } catch (LinkageError e) {
            Krypt04McgMod.LOGGER.warn("Unable to load Krypt04Mcg settings from Cloth Config; using defaults", e);
        }
        return new Krypt04McgConfig();
    }

    public static void registerSaveListener(Consumer<Krypt04McgConfig> listener) {
        if (!FabricLoader.getInstance().isModLoaded(CLOTH_CONFIG_MOD_ID)) {
            return;
        }
        try {
            ClothConfigBridge.registerSaveListener(listener);
        } catch (LinkageError e) {
            Krypt04McgMod.LOGGER.warn("Unable to register Krypt04Mcg Cloth Config save listener", e);
        }
    }
}
