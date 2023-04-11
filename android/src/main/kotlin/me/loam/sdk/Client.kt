package me.loam.sdk
import me.loam.sdk.internal.Native
import kotlin.concurrent.thread
import java.net.HttpURLConnection
import java.net.URL

public final class Client(
    val configuration: Configuration,
    val authToken: String,
    private val native: Long
) {
    public constructor(
        configuration: Configuration,
        authToken: String
    ) : this(
        configuration,
        authToken,
        createNative(configuration, authToken)
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
    private companion object {
        fun createNative(configuration: Configuration, authToken: String): Long {
            val httpSend = object : Native.HttpSendFn {
                override fun send(httpClient: Long, request: Native.HttpRequest) {
                    thread {
                        val urlConnection = URL(request.url).openConnection() as HttpURLConnection
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
                        response.headers = urlConnection.headerFields.flatMap { (key, values) ->
                            if (key != null) {
                                values.map { Native.HttpHeader(key, it) }
                            } else {
                                emptyList()
                            }
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

            return Native.clientCreate(configuration, authToken, httpSend)
        }
    }
}
