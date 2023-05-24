package xyz.juicebox.sdk

/**
 * An error returned from [Client.recover]
 */
public enum class RecoverError {
    /**
     * The secret could not be unlocked, but you can try again
     * with a different PIN if you have guesses remaining. If no
     * guesses remain, this secret is locked and inaccessible.
     */
    INVALID_PIN,

    /**
     * The secret was not registered or not fully registered with the
     * provided realms.
     */
    NOT_REGISTERED,

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
 * An exception thrown from [Client.recover]
 *
 * @property error The underlying error that triggered this exception.
 * @property guessesRemaining The guesses remaining, if the underlying
 * error is [RecoverError.INVALID_PIN].
 */
public class RecoverException(val error: RecoverError, val guessesRemaining: Short?) : Exception(error.name)
