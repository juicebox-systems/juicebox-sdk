package xyz.juicebox.sdk

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import xyz.juicebox.sdk.*
import xyz.juicebox.sdk.internal.Native

@RunWith(AndroidJUnit4::class)
class ClientTest {
    @Test
    fun testJsonConfiguration() {
        val configuration = Configuration("""
          {
            "realms": [
              {
                "address": "https://juicebox.hsm.realm.address",
                "id": "0102030405060708090a0b0c0d0e0f10",
                "public_key": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
              },
              {
                "address": "https://your.software.realm.address",
                "id": "2102030405060708090a0b0c0d0e0f10"
              },
              {
                "address": "https://juicebox.software.realm.address",
                "id": "3102030405060708090a0b0c0d0e0f10"
              }
            ],
            "register_threshold": 3,
            "recover_threshold": 3,
            "pin_hashing_mode": "Standard2019"
          }
        """)
        val expectedConfiguration = Configuration(
            realms = arrayOf(
                Realm(
                    id = RealmId(string = "0102030405060708090a0b0c0d0e0f10"),
                    address = "https://juicebox.hsm.realm.address",
                    publicKey = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".decodeHex()
                ),
                Realm(
                    id = RealmId(string = "2102030405060708090a0b0c0d0e0f10"),
                    address = "https://your.software.realm.address"
                ),
                Realm(
                    id = RealmId(string = "3102030405060708090a0b0c0d0e0f10"),
                    address = "https://juicebox.software.realm.address"
                )
            ),
            registerThreshold = 3,
            recoverThreshold = 3,
            pinHashingMode = PinHashingMode.STANDARD_2019
        )
        assertTrue(Native.configurationsAreEqual(expectedConfiguration.native, configuration.native))
    }

    @Test
    fun testAuthTokenGenerator() {
        val generator = AuthTokenGenerator("""
          {
            "key": "0668e97c5d282a08d4251255541845e2d78b78b9438e1562b51d9cf4e099be53",
            "tenant": "acme",
            "version": 1
          }
        """)
        val realmId = RealmId("000102030405060708090A0B0C0D0E0F")
        val userId = UserId.random()
        val client = Client(
            Configuration(
                realms = arrayOf(Realm(
                    id = realmId,
                    address = "https://httpbin.org/anything/"
                )),
                registerThreshold = 1,
                recoverThreshold = 1,
                pinHashingMode = PinHashingMode.FAST_INSECURE
            )
        )
        Client.fetchAuthTokenCallback = { realmId -> generator.vend(realmId, userId) }
        val exception = assertThrows(RegisterException::class.java) {
            runBlocking {
                client.register("test".toByteArray(), "secret".toByteArray(), "info".toByteArray(), 5)
            }
        }
        assertEquals(RegisterError.ASSERTION, exception.error)
    }

    @Test
    fun testRegister() {
        val client = client("https://httpbin.org/anything/")
        val exception = assertThrows(RegisterException::class.java) {
            runBlocking {
                client.register("test".toByteArray(), "secret".toByteArray(), "info".toByteArray(), 5)
            }
        }
        assertEquals(RegisterError.ASSERTION, exception.error)
    }

    @Test
    fun testRecover() {
        val client = client("https://httpbin.org/anything/")
        val exception = assertThrows(RecoverException::class.java) {
            runBlocking {
                client.recover("test".toByteArray(), "info".toByteArray())
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

    private fun client(url: String): Client {
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
            authTokens = mapOf(realmId to AuthToken("abc.123"))
        )
    }
}
