import ArgumentParser
import JuiceboxSdk
import Foundation

@main
struct Demo: AsyncParsableCommand {
    @Option(name: .shortAndLong, help: "The configuration for the client SDK, in JSON format")
    var configuration: Configuration

    @Option(
        name: .shortAndLong,
        help: "The auth tokens for the client SDK, as a JSON string mapping realm ID to base64-encoded JWT"
    )
    var authTokens: [RealmId: AuthToken]

    @Option(
        name: .shortAndLong,
        help: "The path to the TLS certificate used by the realms",
        transform: { URL(string: "file://" + $0 ) }
    )
    var tlsCertificate: URL?

    // swiftlint:disable cyclomatic_complexity
    // swiftlint:disable:next function_body_length
    mutating func run() async throws {
        let client = Client(configuration: configuration, authTokens: authTokens)
        if let tlsCertificate = tlsCertificate {
            #if os(Linux)
            print("[Swift] WARNING: pinned TLS certificates unsupported on Linux")
            #else
            Client.pinnedCertificatePaths = [tlsCertificate]
            #endif
        }

        print("[Swift] Starting register (allowing 2 guesses)")
        do {
            try await client.register(
                pin: Data("1234".utf8),
                secret: Data("apollo".utf8),
                info: Data("artemis".utf8),
                guesses: 2
            )
        } catch let error {
            fatalError("[Swift] Register failed \(error)")
        }
        print("[Swift] Register succeeded")

        print("[Swift] Starting recover with wrong PIN (guess 1)")
        do {
            let secret = try await client.recover(
                pin: Data("4321".utf8),
                info: Data("artemis".utf8)
            )
            fatalError("[Swift] Unexpected result from recover: \(String(decoding: secret, as: UTF8.self))")
        } catch RecoverError.invalidPin(let guessesRemaining) {
            assert(guessesRemaining == 1)
            print("[Swift] Recover expectedly unsuccessful")
        }

        print("[Swift] Starting recover with correct PIN (guess 2)")
        do {
            let secret = try await client.recover(
                pin: Data("1234".utf8),
                info: Data("artemis".utf8)
            )
            print("[Swift] Recovered secret: \(String(decoding: secret, as: UTF8.self))")
        } catch RecoverError.invalidPin {
            fatalError("[Swift] Recover unexpectedly failed")
        }

        print("[Swift] Starting recover with wrong PIN (guess 1)")
        do {
            let secret = try await client.recover(
                pin: Data("4321".utf8),
                info: Data("artemis".utf8)
            )
            fatalError("[Swift] Unexpected result from recover: \(String(decoding: secret, as: UTF8.self))")
        } catch RecoverError.invalidPin(let guessesRemaining) {
            assert(guessesRemaining == 1)
            print("[Swift] Recover expectedly unsuccessful")
        }

        print("[Swift] Starting recover with wrong PIN (guess 2)")
        do {
            let secret = try await client.recover(
                pin: Data("4321".utf8),
                info: Data("artemis".utf8)
            )
            fatalError("[Swift] Unexpected result from recover: \(String(decoding: secret, as: UTF8.self))")
        } catch RecoverError.invalidPin(let guessesRemaining) {
            assert(guessesRemaining == 0)
            print("[Swift] Recover expectedly unsuccessful")
        }

        print("[Swift] Starting recover with correct PIN (guess 3)")
        do {
            let secret = try await client.recover(
                pin: Data("1234".utf8),
                info: Data("artemis".utf8)
            )
            fatalError("[Swift] Unexpected result from recover: \(String(decoding: secret, as: UTF8.self))")
        } catch RecoverError.invalidPin(let guessesRemaining) {
            assert(guessesRemaining == 0)
            print("[Swift] Recover expectedly unsuccessful")
        }

        print("[Swift] Starting register (allowing 2 guesses)")
        do {
            try await client.register(
                pin: Data("1234".utf8),
                secret: Data("artemis".utf8),
                info: Data("apollo".utf8),
                guesses: 2
            )
        } catch let error {
            fatalError("[Swift] Register failed \(error)")
        }
        print("[Swift] Register succeeded")

        print("[Swift] Starting recover with wrong PIN (guess 1)")
        do {
            let secret = try await client.recover(
                pin: Data("4321".utf8),
                info: Data("apollo".utf8)
            )
            fatalError("[Swift] Unexpected result from recover: \(String(decoding: secret, as: UTF8.self))")
        } catch RecoverError.invalidPin(let guessesRemaining) {
            assert(guessesRemaining == 1)
            print("[Swift] Recover expectedly unsuccessful")
        }

        print("[Swift] Starting recover with correct PIN (guess 2)")
        do {
            let secret = try await client.recover(
                pin: Data("1234".utf8),
                info: Data("apollo".utf8)
            )
            print("[Swift] Recovered secret: \(String(decoding: secret, as: UTF8.self))")
        } catch RecoverError.invalidPin {
            fatalError("[Swift] Recover unexpectedly failed")
        }

        print("[Swift] Deleting secret")
        do {
            try await client.delete()
        } catch let error as DeleteError {
            fatalError("[Swift] Delete unexpectedly failed \(error)")
        }
        print("[Swift] Delete succeeded")

        print("[Swift] Starting recover with correct PIN after delete")
        do {
            let secret = try await client.recover(
                pin: Data("1234".utf8),
                info: Data("apollo".utf8)
            )
            fatalError("[Swift] Unexpected result from recover: \(String(decoding: secret, as: UTF8.self))")
        } catch RecoverError.notRegistered {
            print("[Swift] Recover expectedly unsuccessful")
        }
    }
    // swiftlint:enable cyclomatic_complexity
}

extension Dictionary: ExpressibleByArgument where Key == RealmId, Value == AuthToken {
    enum ArgumentError: Error {
        case invalidRealmId
    }

    public init?(argument: String) {
        let decoder = JSONDecoder()
        guard let dictionary = try? decoder.decode([String: String].self, from: Data(argument.utf8)) else {
            return nil
        }
        guard let keysWithValues = try? dictionary.map({ key, value in
            guard let realmId = RealmId(string: key) else { throw ArgumentError.invalidRealmId }
            return (realmId, AuthToken(jwt: value))
        }) else { return nil }
        self = Dictionary(uniqueKeysWithValues: keysWithValues)
    }
}

extension Configuration: ExpressibleByArgument {
    public convenience init?(argument: String) {
        self.init(json: argument)
    }
}

extension URL: ExpressibleByArgument {
    public init?(argument: String) {
        self.init(string: argument)
    }
}
