package xyz.juicebox.sdk

/**
 * An error returned from [Client.delete]
 */
enum class DeleteError {
    /**
     * A realm rejected the [Client]'s auth token.
     */
    INVALID_AUTH,

    /**
     * The SDK software is too old to communicate with this realm and
     * must be upgraded.
     */
    UPGRADE_REQUIRED,

    /**
     * The tenant has exceeded their allowed number of operations. Try again
     * later.
     */
    RATE_LIMIT_EXCEEDED,

    /**
     * A software error has occurred. This request should not be retried
     * with the same parameters. Verify your inputs, check for software
     * updates and try again.
     */
    ASSERTION,

    /**
     * A transient error in sending or receiving requests to a realm.
     * This request may succeed by trying again with the same parameters.
     */
    TRANSIENT,
}

/**
 * An exception thrown from [Client.delete]
 *
 * @property error The underlying error that triggered this exception.
 */
class DeleteException(val error: DeleteError) : Exception(error.name)
