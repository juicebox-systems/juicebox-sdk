package xyz.juicebox.sdk

/**
 * An error returned from [Client.register]
 */
public enum class RegisterError {
    /**
     * A realm rejected the [Client]'s auth token.
     */
    INVALID_AUTH,

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
 * An exception thrown from [Client.register]
 *
 * @property error The underlying error that triggered this exception.
 */
public class RegisterException(val error: RegisterError) : Exception(error.name)
