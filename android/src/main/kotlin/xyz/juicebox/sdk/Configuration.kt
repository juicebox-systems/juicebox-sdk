package xyz.juicebox.sdk

import xyz.juicebox.sdk.internal.Native

/**
 * The parameters used to configure a [Client].
 */
class Configuration private constructor(val native: Long) {
    /**
     * Initializes a new configuration.
     *
     * @param realms The remote services that the client interacts with.
     *
     * There must be between `registerThreshold` and 255 realms, inclusive.
     *
     * @param registerThreshold A registration will be considered successful
     * if it's successful on at least this many realms.
     *
     * Must be between `recoverThreshold` and `realms.size`, inclusive.
     *
     * @param recoverThreshold A recovery (or an adversary) will need the
     * cooperation of this many realms to retrieve the secret.
     *
     * Must be between `ceil(realms.size / 2)` and `realms.size`, inclusive.
     *
     * @param pinHashingMode Defines how the provided PIN will be hashed
     * before register and recover operations. Changing modes will make previous
     * secrets stored on the realms inaccessible with the same PIN and should not
     * be done without re-registering secrets.
     */
    constructor(
        realms: Array<Realm>,
        registerThreshold: Byte,
        recoverThreshold: Byte,
        pinHashingMode: PinHashingMode
    ): this(Native.configurationCreate(realms, registerThreshold, recoverThreshold, pinHashingMode))

    /**
     * Initializes a new configuration.
     *
     * @param json A json string representing a juicebox configuration.
     */
    constructor(json: String): this(Native.configurationCreateFromJson(json))

    protected fun finalize() {
        Native.configurationDestroy(native)
    }
}
