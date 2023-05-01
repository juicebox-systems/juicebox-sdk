package me.loam.sdk

public enum class RecoverError {
    INVALID_AUTH,
    INVALID_PIN,
    NOT_REGISTERED,
    TRANSIENT,
    ASSERTION,
}

public class RecoverException(val error: RecoverError, val guessesRemaining: Short?) : Exception(error.name)
