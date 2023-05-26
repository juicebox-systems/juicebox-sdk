package xyz.juicebox.sdk

import com.google.gson.*
import java.lang.reflect.Type

/**
 * The parameters used to configure a [Client].
 *
 * @property realms The remote services that the client interacts with.
 *
 * There must be between `registerThreshold` and 255 realms, inclusive.
 *
 * @property registerThreshold A registration will be considered successful
 * if it's successful on at least this many realms.
 *
 * Must be between `recoverThreshold` and `realms.size`, inclusive.
 *
 * @property recoverThreshold A recovery (or an adversary) will need the
 * cooperation of this many realms to retrieve the secret.
 *
 * Must be between `ceil(realms.size / 2)` and `realms.size`, inclusive.
 *
 * @property pinHashingMode Defines how the provided PIN will be hashed
 * before register and recover operations. Changing modes will make previous
 * secrets stored on the realms inaccessible with the same PIN and should not
 * be done without re-registering secrets.
 */
public final data class Configuration(
    val realms: Array<Realm>,
    val registerThreshold: Byte,
    val recoverThreshold: Byte,
    val pinHashingMode: PinHashingMode,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Configuration

        if (!realms.contentEquals(other.realms)) return false
        if (registerThreshold != other.registerThreshold) return false
        if (recoverThreshold != other.recoverThreshold) return false
        if (pinHashingMode != other.pinHashingMode) return false

        return true
    }

    override fun hashCode(): Int {
        var result = realms.contentHashCode()
        result = 31 * result + registerThreshold
        result = 31 * result + recoverThreshold
        result = 31 * result + pinHashingMode.hashCode()
        return result
    }

    companion object {
        fun fromJson(json: String): Configuration {
            val gson = GsonBuilder().registerTypeAdapter(Configuration::class.java, ConfigurationDeserializer()).create()
            return gson.fromJson(json, Configuration::class.java)
        }
    }
}

class ConfigurationDeserializer : JsonDeserializer<Configuration> {
    override fun deserialize(
        json: JsonElement?,
        typeOfT: Type?,
        context: JsonDeserializationContext?
    ): Configuration {
        val jsonObject = json?.asJsonObject

        val realmsJsonArray = jsonObject?.getAsJsonArray("realms")
        val realms = realmsJsonArray?.map { realmJsonElement ->
            val realmJsonObject = realmJsonElement.asJsonObject
            val id = realmJsonObject.get("id").asString?: throw java.lang.Exception("Missing realm id")
            val address = realmJsonObject.get("address").asString?: throw java.lang.Exception("Missing realm address")
            val publicKey = realmJsonObject.get("public_key")?.asString?.let { it.decodeHex() }

            Realm(RealmId(string = id), address, publicKey)
        }?: throw java.lang.Exception("Invalid realms")

        val registerThreshold = jsonObject?.get("register_threshold")?.asByte
            ?: throw java.lang.Exception("Missing register_threshold")

        val recoverThreshold = jsonObject?.get("recover_threshold")?.asByte
            ?: throw java.lang.Exception("Missing recover_threshold")

        val pinHashingMode = when (jsonObject?.get("pin_hashing_mode")?.asString) {
            "Standard2019" -> PinHashingMode.STANDARD_2019
            "FastInsecure" -> PinHashingMode.FAST_INSECURE
            else -> throw java.lang.Exception("Unexpected pin_hashing_mode")
        }

        return Configuration(
            realms.toTypedArray(),
            registerThreshold,
            recoverThreshold,
            pinHashingMode
        )
    }
}

fun String.decodeHex(): ByteArray {
    check(length % 2 == 0) { "Must have an even length" }

    return chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
}
