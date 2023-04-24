package me.loam.sdk

public enum class DeleteError {
    INVALID_AUTH,
    TRANSIENT,
    ASSERTION,
}

public class DeleteException(val error: DeleteError) : Exception(error.name)
