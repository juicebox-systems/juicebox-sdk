import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import xyz.juicebox.sdk.*
import kotlinx.coroutines.*
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.ByteBuffer
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

    fun client(url: String): Client {
        val realmId = RealmId(string = "000102030405060708090A0B0C0D0E0F")
        return Client(
            Configuration(
                realms = arrayOf(Realm(
                    id = realmId,
                    address = url,
                    publicKey = ByteArray(32)
                )),
                registerThreshold = 1,
                recoverThreshold = 1,
                pinHashingMode = PinHashingMode.FAST_INSECURE
            ),
            authTokens = mapOf(realmId to "abc.123")
        )
    }
}
