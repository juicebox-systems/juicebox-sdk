package me.loam.sdk

public enum class RegisterError {
    INVALID_AUTH,
    TRANSIENT,
    ASSERTION,
}

public class RegisterException(val error: RegisterError) : Exception(error.name)
