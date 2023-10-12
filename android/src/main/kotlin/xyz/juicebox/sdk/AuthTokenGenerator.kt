package xyz.juicebox.sdk

import xyz.juicebox.sdk.internal.Native

/**
 * A generator used to vend [AuthToken]s.
 */
class AuthTokenGenerator private constructor(val native: Long) {
    /**
     * Initializes a new generator.
     *
     * @param json A json string representing a generator's parameters.
     */
    constructor(json: String): this(Native.authTokenGeneratorCreateFromJson(json))

    protected fun finalize() {
        Native.authTokenGeneratorDestroy(native)
    }

    public fun vend(realmId: RealmId, userId: UserId): AuthToken {
        return AuthToken(native = Native.authTokenGeneratorVend(native, realmId.bytes, userId.bytes))
    }
}
