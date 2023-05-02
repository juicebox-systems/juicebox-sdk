package me.loam.sdk

/**
 * A strategy for hashing the user provided pin.
 */
public enum class PinHashingMode {
    /**
     * No hashing, ensure a PIN of sufficient entropy is provided.
     */
    NONE,

    /**
     * A tuned hash, secure for use on modern devices as of 2019 with low-entropy PINs.
     */
    STANDARD_2019,

    /**
     * A fast hash used for testing. Do not use in production.
     */
    FAST_INSECURE,
}
