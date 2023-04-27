package me.loam.sdk

public enum class DeleteError {
    INVALID_AUTH,
    ASSERTION,
    TRANSIENT,
}

public class DeleteException(val error: DeleteError) : Exception(error.name)
