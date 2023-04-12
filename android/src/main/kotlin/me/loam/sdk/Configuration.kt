package me.loam.sdk

public final data class Configuration(
    val realms: Array<Realm>,
    val registerThreshold: Byte,
    val recoverThreshold: Byte
)
