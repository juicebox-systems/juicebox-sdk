import XCTest
@testable import JuiceboxSdk
import JuiceboxSdkFfi

final class JuiceboxSdkTests: XCTestCase {
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
