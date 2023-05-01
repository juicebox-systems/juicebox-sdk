import XCTest
@testable import LoamSdk
import LoamSdkFfi

final class LoamSdkTests: XCTestCase {
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
        Client(
            configuration: .init(
                realms: [
                    .init(
                        id: .init(),
                        address: URL(string: url)!,
                        publicKey: Data(repeating: 0, count: 32)
                    )
                ],
                registerThreshold: 1,
                recoverThreshold: 1,
                pinHashingMode: .none
            ),
            authToken: "abc.123"
        )
    }
}
