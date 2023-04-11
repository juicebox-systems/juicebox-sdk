import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import me.loam.sdk.*
import kotlinx.coroutines.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ClientTest {
    @Test
    fun testRegister() = runBlocking {
        val client = client("https://httpbin.org/anything/")
        try {
            client.register("test".toByteArray(), "secret".toByteArray(), 5)
        } catch (e: RegisterException) {
            assertEquals(RegisterError.PROTOCOL, e.error)
        }
    }

    @Test
    fun testRecover() = runBlocking {
        val client = client("https://httpbin.org/anything/")
        try {
            val secret = client.recover("test".toByteArray())
            assertNull(secret)
        } catch (e: RecoverException) {
            assertEquals(RecoverError.PROTOCOL, e.error)
        }
    }

    @Test
    fun testDelete() = runBlocking {
        val client = client("https://httpbin.org/anything/")
        try {
            client.deleteAll()
        } catch (e: DeleteException) {
            assertEquals(DeleteError.PROTOCOL, e.error)
        }
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
                recoverThreshold = 1
            ),
            "test"
        )
    }
}
