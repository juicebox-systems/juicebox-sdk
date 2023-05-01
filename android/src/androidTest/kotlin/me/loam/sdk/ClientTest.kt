import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import me.loam.sdk.*
import kotlinx.coroutines.*
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import java.security.cert.CertificateFactory

@RunWith(AndroidJUnit4::class)
class ClientTest {
    @Test
    fun testRegister() {
        val client = client("https://httpbin.org/anything/")
        val exception = assertThrows(RegisterException::class.java) {
            runBlocking {
                client.register("test".toByteArray(), "secret".toByteArray(), 5)
            }
        }
        assertEquals(RegisterError.ASSERTION, exception.error)
    }

    @Test
    fun testRecover() {
        val client = client("https://httpbin.org/anything/")
        val exception = assertThrows(RecoverException::class.java) {
            runBlocking {
                client.recover("test".toByteArray())
            }
        }
        assertEquals(RecoverError.ASSERTION, exception.error)
    }

    @Test
    fun testDelete() {
        val client = client("https://httpbin.org/anything/")
        val exception = assertThrows(DeleteException::class.java) {
            runBlocking {
                client.delete()
            }
        }
        assertEquals(DeleteError.ASSERTION, exception.error)
    }

    @Ignore
    @Test
    fun testEndToEnd(): Unit = runBlocking {
        // TODO: Figure out how to plumb demo runner config here, for now you can setup
        // the info below manually after running ./demo_runner --keep-alive
        val client = Client(
            Configuration(
                realms = arrayOf(
                    Realm(
                        id = ubyteArrayOf(67u,69u,113u,199u,4u,248u,148u,16u,58u,22u,114u,107u,91u,103u,71u,243u).toByteArray(),
                        address = "https://10.0.2.2:3001/",
                        publicKey = ubyteArrayOf(63u,63u,161u,56u,150u,103u,240u,18u,89u,73u,102u,165u,63u,179u,2u,170u,109u,75u,159u,225u,148u,28u,90u,198u,49u,10u,42u,52u,24u,85u,22u,69u).toByteArray()
                    ),
                    Realm(
                        id = ubyteArrayOf(82u,77u,12u,205u,7u,17u,27u,212u,175u,148u,69u,73u,69u,115u,142u,239u).toByteArray(),
                        address = "https://10.0.2.2:3002/",
                        publicKey = ubyteArrayOf(53u,167u,49u,201u,190u,60u,34u,52u,192u,219u,180u,183u,54u,32u,32u,61u,79u,87u,113u,160u,131u,240u,242u,63u,229u,167u,113u,88u,164u,67u,53u,126u).toByteArray()
                    ),
                    Realm(
                        id = ubyteArrayOf(48u,218u,88u,53u,102u,223u,164u,165u,253u,206u,207u,172u,141u,188u,215u,120u).toByteArray(),
                        address = "https://10.0.2.2:3001/",
                        publicKey = ubyteArrayOf(253u,140u,243u,0u,29u,252u,191u,113u,90u,104u,208u,215u,224u,52u,163u,162u,81u,191u,217u,65u,166u,202u,16u,211u,40u,123u,105u,249u,93u,68u,153u,92u).toByteArray()
                    ),
                    Realm(
                        id = ubyteArrayOf(14u,160u,128u,221u,194u,246u,54u,160u,204u,76u,172u,21u,221u,105u,161u,3u).toByteArray(),
                        address = "https://10.0.2.2:3002/",
                        publicKey = ubyteArrayOf(215u,170u,166u,75u,35u,145u,212u,250u,165u,121u,153u,25u,68u,183u,230u,1u,170u,47u,223u,202u,128u,192u,144u,196u,29u,95u,201u,134u,36u,161u,253u,40u).toByteArray()
                    )
                ),
                registerThreshold = 3,
                recoverThreshold = 3,
                pinHashingMode = PinHashingMode.FAST_INSECURE
            ),
            authToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0Iiwic3ViIjoibWFyaW8iLCJhdWQiOiJsb2FtLm1lIiwiZXhwIjoxNjgxMjQ1MjE1LCJuYmYiOjE2ODEyNDQ2MDV9.xJD1x9i0mlrEVlcmiDxpXVX84GZGnlT1egraN2QEVgs"
        )
        Client.pinnedCertificates = arrayOf(
            CertificateFactory.getInstance("X.509").generateCertificate(InstrumentationRegistry.getInstrumentation().context.assets.open("localhost.cert.der"))
        )

        Log.i("ClientTest", "Starting register (allowing 2 guesses)")
        client.register("1234".toByteArray(), "apollo".toByteArray(), 2)
        Log.i("ClientTest", "Register succeeded")

        Log.i("ClientTest", "Starting recover with wrong PIN (guess 1)")
        val exception1 = assertThrows(RecoverException::class.java) {
            runBlocking {
                client.recover("4321".toByteArray())
            }
        }
        assertEquals(RecoverError.INVALID_PIN, exception1.error)
        assertEquals(1.toShort(), exception1.guessesRemaining)
        Log.i("ClientTest", "Recover expectedly unsuccessful")

        Log.i("ClientTest", "Starting recover with correct PIN (guess 2)")
        val secret1 = String(client.recover("1234".toByteArray()))
        assertEquals("apollo", secret1)
        Log.i("ClientTest", "Recovered secret: $secret1")

        Log.i("ClientTest", "Starting recover with wrong PIN (guess 1)")
        val exception2 = assertThrows(RecoverException::class.java) {
            runBlocking {
                client.recover("4321".toByteArray())
            }
        }
        assertEquals(RecoverError.INVALID_PIN, exception2.error)
        assertEquals(1.toShort(), exception2.guessesRemaining)
        Log.i("ClientTest", "Recover expectedly unsuccessful")

        Log.i("ClientTest", "Starting recover with wrong PIN (guess 2)")
        val exception3 = assertThrows(RecoverException::class.java) {
            runBlocking {
                client.recover("4321".toByteArray())
            }
        }
        assertEquals(RecoverError.INVALID_PIN, exception3.error)
        assertEquals(0.toShort(), exception3.guessesRemaining)
        Log.i("ClientTest", "Recover expectedly unsuccessful")

        Log.i("ClientTest", "Starting recover with correct PIN (guess 3)")
        val exception4 = assertThrows(RecoverException::class.java) {
            runBlocking {
                client.recover("1234".toByteArray())
            }
        }
        assertEquals(RecoverError.INVALID_PIN, exception4.error)
        Log.i("ClientTest", "Recover expectedly unsuccessful")

        Log.i("ClientTest", "Starting register (allowing 2 guesses)")
        client.register("abcd".toByteArray(), "artemis".toByteArray(), 2)
        Log.i("ClientTest", "Register succeeded")

        Log.i("ClientTest", "Starting recover with wrong PIN (guess 1)")
        val exception5 = assertThrows(RecoverException::class.java) {
            runBlocking {
                client.recover("zyxw".toByteArray())
            }
        }
        assertEquals(RecoverError.INVALID_PIN, exception5.error)
        assertEquals(1.toShort(), exception5.guessesRemaining)
        Log.i("ClientTest", "Recover expectedly unsuccessful")

        Log.i("ClientTest", "Starting recover with correct PIN (guess 2)")
        val secret2 = String(client.recover("abcd".toByteArray()))
        assertEquals("artemis", secret2)
        Log.i("ClientTest", "Recovered secret: $secret2")

        Log.i("ClientTest", "Deleting secret")
        client.delete()
        Log.i("ClientTest", "Delete succeeded")

        Log.i("ClientTest", "Starting recover with correct PIN after delete")
        val exception6 = assertThrows(RecoverException::class.java) {
            runBlocking {
                client.recover("abcd".toByteArray())
            }
        }
        assertEquals(RecoverError.NOT_REGISTERED, exception6.error)
        assertEquals(null, exception6.guessesRemaining)
        Log.i("ClientTest", "Recover expectedly unsuccessful")
    }

    fun client(url: String): Client {
        return Client(
            Configuration(
                realms = arrayOf(Realm(
                    id = ByteArray(16),
                    address = url,
                    publicKey = ByteArray(32)
                )),
                registerThreshold = 1,
                recoverThreshold = 1,
                pinHashingMode = PinHashingMode.NONE
            ),
            authToken = "test"
        )
    }
}
