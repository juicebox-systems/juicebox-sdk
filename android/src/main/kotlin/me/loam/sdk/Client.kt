package me.loam.sdk
import me.loam.sdk.internal.Native
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
public final class Client private constructor (
    val configuration: Configuration,
    val previousConfigurations: Array<Configuration>,
    val authToken: String,
    private val native: Long
) {
    /**
     * Initializes a new client with the provided configuration and auth token.
     *
     * @param configuration Represents the current configuration. The configuration
     * provided must include at least one [Realm].
     * @param previousConfigurations Represents any other configurations you have
     * previously registered with that you may not yet have migrated the data from.
     * @param authToken Represents the authority to act as a particular user
     * and should be valid for the lifetime of the [Client].
     */
    public constructor(
        configuration: Configuration,
        previousConfigurations: Array<Configuration> = emptyArray(),
        authToken: String
    ) : this(
        configuration,
        previousConfigurations,
        authToken,
        createNative(configuration, previousConfigurations, authToken)
    ) {}

    /**
     * Stores a new PIN-protected secret on the configured realms.
     *
     * @param pin A user provided PIN. If using a strong [PinHashingMode], this can
     * safely be a low-entropy value.
     * @param secret A user provided secret.
     * @param numGuesses The number of guesses allowed before the secret can no longer
     * be accessed.
     *
     * @throws [RegisterException] if registration could not be completed successfully.
     */
    @Throws(RegisterException::class)
    public suspend fun register(pin: ByteArray, secret: ByteArray, numGuesses: Short) {
        Native.clientRegister(native, pin, secret, numGuesses)
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
    public suspend fun recover(pin: ByteArray): ByteArray {
        return Native.clientRecover(native, pin)
    }

    /**
     * Deletes all secrets for this user.
     *
     * *Note:* This does not delete the user's audit log.
     *
     * @throws [DeleteException] if deletion could not be completed successfully.
     */
    @Throws(DeleteException::class)
    public suspend fun deleteAll() {
        Native.clientDeleteAll(native)
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
        public var pinnedCertificates: Array<Certificate>? = null

        private fun createNative(configuration: Configuration, previousConfigurations: Array<Configuration>, authToken: String): Long {
            val httpSend = Native.HttpSendFn { httpClient, request ->
                thread {
                    val urlConnection = URL(request.url).openConnection() as HttpsURLConnection

                    Client.pinnedCertificates?.let {
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
                        response.body = urlConnection.inputStream.readAllBytes()
                    } else {
                        response.body = urlConnection.errorStream.readAllBytes()
                    }

                    Native.httpClientRequestComplete(httpClient, response)
                }
            }

            return Native.clientCreate(configuration, previousConfigurations, authToken, httpSend)
        }
    }
}
