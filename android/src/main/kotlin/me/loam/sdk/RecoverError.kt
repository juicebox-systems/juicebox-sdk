package me.loam.sdk

public enum class RecoverError {
    INVALID_PIN,
    NOT_REGISTERED,
    INVALID_AUTH,
    ASSERTION,
    TRANSIENT,
}

public class RecoverException(val error: RecoverError, val guessesRemaining: Short?) : Exception(error.name)
