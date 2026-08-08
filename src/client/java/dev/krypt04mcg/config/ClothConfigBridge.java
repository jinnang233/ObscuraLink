package dev.krypt04mcg.config;

import me.shedaniel.autoconfig.AutoConfig;
import me.shedaniel.autoconfig.ConfigHolder;
import me.shedaniel.autoconfig.serializer.GsonConfigSerializer;
import net.minecraft.world.InteractionResult;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public final class ClothConfigBridge {
    private static boolean registered;
    private static Krypt04McgConfig runtimeConfig;
    private static final List<Consumer<Krypt04McgConfig>> SAVE_LISTENERS = new ArrayList<>();

    private ClothConfigBridge() {
    }

    public static Krypt04McgConfig load() {
        register();
        ConfigHolder<ClothKrypt04McgConfig> holder = AutoConfig.getConfigHolder(ClothKrypt04McgConfig.class);
        if (runtimeConfig == null) {
            runtimeConfig = holder.getConfig().toCoreConfig();
        } else {
            holder.getConfig().copyTo(runtimeConfig);
        }
        return runtimeConfig;
    }

    public static void registerSaveListener(Consumer<Krypt04McgConfig> listener) {
        register();
        SAVE_LISTENERS.add(listener);
    }

    private static void register() {
        if (registered) {
            return;
        }
        AutoConfig.register(ClothKrypt04McgConfig.class, GsonConfigSerializer::new);
        AutoConfig.getConfigHolder(ClothKrypt04McgConfig.class).registerSaveListener((holder, config) -> {
            if (runtimeConfig != null) {
                config.copyTo(runtimeConfig);
                SAVE_LISTENERS.forEach(listener -> listener.accept(runtimeConfig));
            }
            return InteractionResult.SUCCESS;
        });
        registered = true;
    }
}
