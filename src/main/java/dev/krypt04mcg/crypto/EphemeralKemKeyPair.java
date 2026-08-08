package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.KemAlgorithm;

import java.util.Arrays;

public final class EphemeralKemKeyPair implements AutoCloseable {
    private final KemAlgorithm algorithm;
    private final byte[] publicKey;
    private final byte[] privateKey;
    private boolean destroyed;

    EphemeralKemKeyPair(KemAlgorithm algorithm, byte[] publicKey, byte[] privateKey) {
        this.algorithm = algorithm;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public KemAlgorithm algorithm() {
        return algorithm;
    }

    public synchronized byte[] publicKey() {
        ensureAvailable();
        return publicKey.clone();
    }

    synchronized byte[] privateKey() {
        ensureAvailable();
        return privateKey;
    }

    public synchronized boolean destroyed() {
        return destroyed;
    }

    @Override
    public synchronized void close() {
        Arrays.fill(publicKey, (byte) 0);
        Arrays.fill(privateKey, (byte) 0);
        destroyed = true;
    }

    private void ensureAvailable() {
        if (destroyed) {
            throw new IllegalStateException("Ephemeral KEM key has been destroyed");
        }
    }
}
