import XCTest
@testable import LoamSdk
import LoamSdkFfi

final class LoamSdkTests: XCTestCase {
    func testRegisterRequestError() async throws {
        let client = client(url: "https://httpbin.org/anything/")
        do {
            try await client.register(pin: Data(), secret: Data(), guesses: 5)
        } catch let error as LoamRegisterError {
            XCTAssertEqual(LoamRegisterErrorProtocolError, error)
        }
    }

    func testRecoverRequestError() async throws {
        let client = client(url: "https://httpbin.org/anything/")
        do {
            let secret = try await client.recover(pin: Data())
            XCTAssertNil(secret)
        } catch let error as LoamRecoverError {
            XCTAssertEqual(LoamRecoverErrorProtocolError, error)
        }
    }

    func testDeleteRequestError() async throws {
        let client = client(url: "https://httpbin.org/anything/")
        do {
            try await client.deleteAll()
        } catch let error as LoamDeleteError {
            XCTAssertEqual(LoamDeleteErrorProtocolError, error)
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
                recoverThreshold: 1
            ),
            authToken: .init(
                tenant: "abc",
                user: "123",
                signature: Data()
            )
        )
    }
}
