package xyz.juicebox.sdk

/**
 * A remote service that the client interacts with directly.
 *
 * @property id A unique identifier specified by the realm.
 * @property address The network address to connect to the service.
 * @property publicKey A long-lived public key for which a hardware
 * backed service maintains a matching private key. Software realms
 * do not require public keys.
 */
public final data class Realm(
    val id: ByteArray,
    val address: String,
    val publicKey: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Realm

        if (!id.contentEquals(other.id)) return false
        if (address != other.address) return false
        if (!publicKey.contentEquals(other.publicKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.contentHashCode()
        result = 31 * result + address.hashCode()
        result = 31 * result + publicKey.contentHashCode()
        return result
    }
}
