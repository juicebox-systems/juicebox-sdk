package xyz.juicebox.sdk

import xyz.juicebox.sdk.internal.Native

/**
 * A token used to authenticate with a [Realm].
 */
class AuthToken constructor(val native: Long) {
    /**
     * Initializes a new token.
     *
     * @param jwt The JWT string vended by a tenant server.
     */
    constructor(
        jwt: String
    ): this(Native.authTokenCreate(jwt))

    protected fun finalize() {
        Native.authTokenDestroy(native)
    }
}
