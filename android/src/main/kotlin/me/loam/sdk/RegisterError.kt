package me.loam.sdk

public enum class RegisterError {
    INVALID_AUTH,
    ASSERTION,
    TRANSIENT,
}

public class RegisterException(val error: RegisterError) : Exception(error.name)
