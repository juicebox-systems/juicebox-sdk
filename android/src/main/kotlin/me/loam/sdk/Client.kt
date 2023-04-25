package me.loam.sdk
import me.loam.sdk.internal.Native
import java.net.URL
import java.security.KeyStore
import java.security.cert.Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import kotlin.concurrent.thread
public final class Client(
    val configuration: Configuration,
    val previousConfigurations: Array<Configuration>,
    val authToken: String,
    private val native: Long
) {
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

    public suspend fun register(pin: ByteArray, secret: ByteArray, numGuesses: Short) {
        Native.clientRegister(native, pin, secret, numGuesses)
    }

    public suspend fun recover(pin: ByteArray): ByteArray {
        return Native.clientRecover(native, pin)
    }

    public suspend fun deleteAll() {
        Native.clientDeleteAll(native)
    }

    protected fun finalize() {
        Native.clientDestroy(native)
    }

    companion object {
        public var pinnedCertificates: Array<Certificate>? = null

        private fun createNative(configuration: Configuration, previousConfigurations: Array<Configuration>, authToken: String): Long {
            val httpSend = object : Native.HttpSendFn {
                override fun send(httpClient: Long, request: Native.HttpRequest) {
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
            }

            return Native.clientCreate(configuration, previousConfigurations, authToken, httpSend)
        }
    }
}
