package xyz.juicebox.sdk

/**
 * The parameters used to configure a [Client].
 *
 * @property realms The remote services that the client interacts with.
 *
 * There must be between `registerThreshold` and 255 realms, inclusive.
 *
 * @property registerThreshold A registration will be considered successful
 * if it's successful on at least this many realms.
 *
 * Must be between `recoverThreshold` and `realms.size`, inclusive.
 *
 * @property recoverThreshold A recovery (or an adversary) will need the
 * cooperation of this many realms to retrieve the secret.
 *
 * Must be between `ceil(realms.size / 2)` and `realms.size`, inclusive.
 *
 * @property pinHashingMode Defines how the provided PIN will be hashed
 * before register and recover operations. Changing modes will make previous
 * secrets stored on the realms inaccessible with the same PIN and should not
 * be done without re-registering secrets.
 */
public final data class Configuration(
    val realms: Array<Realm>,
    val registerThreshold: Byte,
    val recoverThreshold: Byte,
    val pinHashingMode: PinHashingMode,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Configuration

        if (!realms.contentEquals(other.realms)) return false
        if (registerThreshold != other.registerThreshold) return false
        if (recoverThreshold != other.recoverThreshold) return false
        if (pinHashingMode != other.pinHashingMode) return false

        return true
    }

    override fun hashCode(): Int {
        var result = realms.contentHashCode()
        result = 31 * result + registerThreshold
        result = 31 * result + recoverThreshold
        result = 31 * result + pinHashingMode.hashCode()
        return result
    }
}
