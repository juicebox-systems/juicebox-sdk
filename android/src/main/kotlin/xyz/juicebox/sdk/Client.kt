package xyz.juicebox.sdk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import xyz.juicebox.sdk.internal.Native
import java.net.URL
import java.security.KeyStore
import java.security.cert.Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import kotlin.concurrent.thread

/**
 * Register and recover PIN-protected secrets on behalf of a particular user.
 */
class Client private constructor (
    private val native: Long
) {
    /**
     * Initializes a new client with the provided configuration and auth token.
     *
     * @param configuration Represents the current configuration. The configuration
     * provided must include at least one [Realm].
     * @param previousConfigurations Represents any other configurations you have
     * previously registered with that you may not yet have migrated the data from.
     * During [recover], they will be tried if the current user has not yet
     * registered on the current configuration. These should be ordered from most recently
     * to least recently used.
     * @param authTokens Represents the authority to act as a particular user on a particular
     * realm and should be valid for the lifetime of the [Client]. Alternatively, you
     * may omit this argument and implement [Client.fetchAuthTokenCallback]
     * to fetch and refresh tokens as needed.
     */
    constructor(
        configuration: Configuration,
        previousConfigurations: Array<Configuration> = emptyArray(),
        authTokens: Map<RealmId, String>? = null
    ) : this(
        createNative(configuration, previousConfigurations, authTokens)
    )

    /**
     * Stores a new PIN-protected secret on the configured realms.
     *
     * @param pin A user provided PIN. If using a strong [PinHashingMode], this can
     * safely be a low-entropy value.
     * @param secret A user provided secret with a maximum length of 128-bytes.
     * @param numGuesses The number of guesses allowed before the secret can no longer
     * be accessed.
     *
     * @throws [RegisterException] if registration could not be completed successfully.
     */
    @Throws(RegisterException::class)
    suspend fun register(pin: ByteArray, secret: ByteArray, numGuesses: Short) {
        withContext(Dispatchers.IO) {
            Native.clientRegister(native, pin, secret, numGuesses)
        }
    }

    /**
     * Retrieves a PIN-protected secret from the configured realms, or falls back to the
     * previous realms if the current realms do not have any secret registered.
     *
     * @param pin A user provided PIN. If using a strong [PinHashingMode], this can
     * safely be a low-entropy value.
     *
     * @return secret The recovered user provided secret.
     *
     * @throws [RecoverException] if recovery could not be completed successfully.
     */
    @Throws(RecoverException::class)
    suspend fun recover(pin: ByteArray): ByteArray {
        return withContext(Dispatchers.IO) {
            Native.clientRecover(native, pin)
        }
    }

    /**
     * Deletes the registered secret for this user, if any.
     *
     * @throws [DeleteException] if deletion could not be completed successfully.
     */
    @Throws(DeleteException::class)
    suspend fun delete() {
        withContext(Dispatchers.IO) {
            Native.clientDelete(native)
        }
    }

    protected fun finalize() {
        Native.clientDestroy(native)
    }

    companion object {
        /**
         * The file path of any certificate files you wish to pin realm connections against.
         *
         * If no paths are provided, connection to realms will be permitted as long as they are
         * using a certificate issued by a trusted authority.
         *
         * *Note:* Certificates should be provided in DER format.
         */
        var pinnedCertificates: Array<Certificate>? = null

        /**
         * Called when any client requires an auth token for a given realm. In general,
         * it's recommended you maintain some form of cache for tokens and do not fetch
         * a fresh token for every request. Said cache should be invalidated if any operation
         * returns an `InvalidAuth` error.
         */
        var fetchAuthTokenCallback: ((RealmId) -> String?)? = null

        private fun createNative(configuration: Configuration, previousConfigurations: Array<Configuration>, authTokens: Map<RealmId, String>?): Long {
            val httpSend = Native.HttpSendFn { httpClient, request ->
                thread {
                    val urlConnection = URL(request.url).openConnection() as HttpsURLConnection

                    pinnedCertificates?.let {
                        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
                        keyStore.load(null, null)
                        it.forEachIndexed { index, certificate ->
                            keyStore.setCertificateEntry(index.toString(), certificate)
                        }

                        val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                        trustManagerFactory.init(keyStore)
                        val trustManagers = trustManagerFactory.trustManagers

                        val sslContext = SSLContext.getInstance("TLS")
                        sslContext.init(null, trustManagers, null)
                        urlConnection.sslSocketFactory = sslContext.socketFactory
                    }

                    urlConnection.requestMethod = request.method

                    request.headers?.forEach {
                        urlConnection.setRequestProperty(it.name, it.value)
                    }

                    urlConnection.doInput = true
                    request.body?.let {
                        urlConnection.doOutput = true
                        urlConnection.outputStream.write(it)
                    }

                    val response = Native.HttpResponse()

                    response.id = request.id
                    response.statusCode = urlConnection.responseCode.toShort()
                    response.headers = urlConnection.headerFields.filterKeys { it != null }.map { (key, values) ->
                        Native.HttpHeader(key, values.joinToString(","))
                    }.toTypedArray()

                    if (response.statusCode == 200.toShort()) {
                        response.body = urlConnection.inputStream.readBytes()
                    } else {
                        response.body = urlConnection.errorStream.readBytes()
                    }

                    Native.httpClientRequestComplete(httpClient, response)
                }
            }

            val getAuthToken = Native.GetAuthTokenFn { context, contextId, realmId ->
                thread {
                    authTokens?.let {
                        Native.authTokenGetComplete(context, contextId, it[realmId])
                    } ?: run {
                        fetchAuthTokenCallback?.let { callback ->
                            Native.authTokenGetComplete(context, contextId, callback(realmId))
                        } ?: run {
                            Native.authTokenGetComplete(context, contextId, null)
                        }
                    }
                }
            }

            return Native.clientCreate(
                configuration.native,
                previousConfigurations.map { it.native }.toLongArray(),
                getAuthToken,
                httpSend
            )
        }
    }
}
