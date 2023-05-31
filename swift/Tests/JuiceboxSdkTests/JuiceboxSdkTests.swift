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

    func testRegisterRequestError() async throws {
        let client = client(url: "https://httpbin.org/anything/")
        do {
            try await client.register(pin: Data(), secret: Data(), guesses: 5)
        } catch RegisterError.assertion {

        }
    }

    func testRecoverRequestError() async throws {
        let client = client(url: "https://httpbin.org/anything/")
        do {
            let secret = try await client.recover(pin: Data())
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
        let realmId = RealmId(string: "000102030405060708090A0B0C0D0E0F")!
        return Client(
            configuration: .init(
                realms: [
                    .init(
                        id: realmId,
                        address: URL(string: url)!,
                        publicKey: Data(repeating: 0, count: 32)
                    )
                ],
                registerThreshold: 1,
                recoverThreshold: 1,
                pinHashingMode: .fastInsecure
            ),
            authTokens: [realmId: "fake.token"]
        )
    }
}
