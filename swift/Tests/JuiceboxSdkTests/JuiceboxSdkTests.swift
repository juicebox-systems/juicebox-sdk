import XCTest
@testable import JuiceboxSdk
import JuiceboxSdkFfi

final class JuiceboxSdkTests: XCTestCase {
    func testJsonConfiguration() {
        let configuration = Configuration(json: """
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
        XCTAssertEqual(.init(
            realms: [
                .init(
                    id: .init(string: "0102030405060708090a0b0c0d0e0f10")!,
                    address: .init(string: "https://juicebox.hsm.realm.address")!,
                    publicKey: .init(hexString: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")!
                ),
                .init(
                    id: .init(string: "2102030405060708090a0b0c0d0e0f10")!,
                    address: .init(string: "https://your.software.realm.address")!
                ),
                .init(
                    id: .init(string: "3102030405060708090a0b0c0d0e0f10")!,
                    address: .init(string: "https://juicebox.software.realm.address")!
                )
            ],
            registerThreshold: 3,
            recoverThreshold: 3,
            pinHashingMode: .standard2019
        ), configuration)
    }

    func testAuthTokenGenerator() async throws {
        let generator = AuthTokenGenerator(json: """
          {
            "key": "0668e97c5d282a08d4251255541845e2d78b78b9438e1562b51d9cf4e099be53",
            "tenant": "acme",
            "version": 1
          }
        """)
        let realmId = RealmId(string: "000102030405060708090A0B0C0D0E0F")!
        let secretId = SecretId.random()

        Client.fetchAuthTokenCallback = { generator.vend(realmId: $0, secretId: secretId) }

        let client = Client(
            configuration: .init(
                realms: [
                    .init(
                        id: realmId,
                        address: URL(string: "https://httpbin.org/anything/")!,
                        publicKey: Data(repeating: 0, count: 32)
                    )
                ],
                registerThreshold: 1,
                recoverThreshold: 1,
                pinHashingMode: .fastInsecure
            )
        )

        do {
            try await client.register(pin: Data(), secret: Data(), info: Data(), guesses: 5)
        } catch RegisterError.assertion {

        }
    }

    func testAuthTokenString() async {
        let token = AuthToken(jwt: "x.y.z")
        let string = await token.string()
        XCTAssertEqual(string, "x.y.z")
    }

    func testRegisterRequestError() async throws {
        let client = client(url: "https://httpbin.org/anything/")
        do {
            try await client.register(pin: Data(), secret: Data(), info: Data(), guesses: 5)
        } catch RegisterError.assertion {

        }
    }

    func testRecoverRequestError() async throws {
        let client = client(url: "https://httpbin.org/anything/")
        do {
            let secret = try await client.recover(pin: Data(), info: Data())
            XCTAssertNil(secret)
        } catch RecoverError.assertion {

        }
    }

    func testDeleteRequestError() async throws {
        let client = client(url: "https://httpbin.org/anything/")
        do {
            try await client.delete()
        } catch DeleteError.assertion {

        }
    }

    @discardableResult
    func client(url: String) -> Client {
        let realmId1 = RealmId(string: "000102030405060708090A0B0C0D0E0F")!
        let realmId2 = RealmId(string: "010102030405060708090A0B0C0D0E0F")!
        return Client(
            configuration: .init(
                realms: [
                    .init(
                        id: realmId1,
                        address: URL(string: url)!,
                        publicKey: Data(repeating: 0, count: 32)
                    ),
                    .init(
                        id: realmId2,
                        address: URL(string: url)!,
                        publicKey: Data(repeating: 0, count: 32)
                    )
                ],
                registerThreshold: 2,
                recoverThreshold: 2,
                pinHashingMode: .fastInsecure
            ),
            authTokens: [
                realmId1: AuthToken(jwt: "fake.token1"),
                realmId2: AuthToken(jwt: "fake.token2")
            ]
        )
    }
}
