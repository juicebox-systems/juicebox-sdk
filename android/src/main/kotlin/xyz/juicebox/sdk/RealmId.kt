package xyz.juicebox.sdk

/**
 * A 16-byte unique identifier specified by the realm.
 */
public final data class RealmId(val bytes: ByteArray) {
    public constructor(string: String) : this(string.decodeHex())

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RealmId

        if (!bytes.contentEquals(other.bytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }
}

fun String.decodeHex(): ByteArray {
    check(length % 2 == 0) { "Must have an even length" }

    return chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
}
