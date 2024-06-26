package xyz.juicebox.sdk

import kotlin.random.Random

/**
 * A 16-byte unique identifier for a given secret.
 */
data class SecretId(val bytes: ByteArray) {
    constructor(string: String) : this(string.decodeHex())

    override fun toString(): String {
        return bytes.encodeHex()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SecretId

        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }

    companion object {
        public fun random(): SecretId {
            val bytes = ByteArray(16)
            Random.Default.nextBytes(bytes)
            return SecretId(bytes)
        }
    }
}
