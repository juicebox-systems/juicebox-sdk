package me.loam.sdk

public enum class RecoverError {
    INVALID_AUTH,
    NETWORK,
    UNSUCCESSFUL,
    PROTOCOL,
}

public class RecoverException(val error: RecoverError, val guessesRemaining: Short?) : Exception(error.name)
