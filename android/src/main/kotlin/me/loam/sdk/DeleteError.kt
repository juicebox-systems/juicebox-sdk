package me.loam.sdk

public enum class DeleteError {
    INVALID_AUTH,
    NETWORK,
    PROTOCOL,
}

public class DeleteException(val error: DeleteError) : Exception(error.name)
