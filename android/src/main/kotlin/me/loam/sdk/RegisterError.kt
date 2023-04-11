package me.loam.sdk

public enum class RegisterError {
    INVALID_AUTH,
    NETWORK,
    PROTOCOL,
    UNAVAILABLE,
}

public class RegisterException(val error: RegisterError) : Exception(error.name)
