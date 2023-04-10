import ArgumentParser
import LoamSdk
import Foundation

@main
struct Demo: AsyncParsableCommand {
    @Option(name: .shortAndLong, help: "The configuration for the client SDK, in JSON format")
    var configuration: Configuration

    @Option(name: .shortAndLong, help: "The auth token for the client SDK, as a base64-encoded JWT")
    var authToken: String

    @Option(
        name: .shortAndLong,
        help: "The path to the TLS certificate used by the realms",
        transform: { URL(string: "file://" + $0 ) }
    )
    var tlsCertificate: URL?

    // swiftlint:disable cyclomatic_complexity
    // swiftlint:disable:next function_body_length
    mutating func run() async throws {
        let client = Client(configuration: configuration, authToken: authToken)
        if let tlsCertificate = tlsCertificate {
            #if os(Linux)
            print("[Swift] WARNING: pinned TLS certificates unsupported on Linux")
            #else
            client.pinnedCertificatePaths = [tlsCertificate]
            #endif
        }

        print("[Swift] Starting register (allowing 2 guesses)")
        do {
            try await client.register(
                pin: "1234".data(using: .utf8)!,
                secret: "apollo".data(using: .utf8)!,
                guesses: 2
            )
        } catch let error {
            fatalError("[Swift] Register failed \(error)")
        }
        print("[Swift] Register succeeded")

        print("[Swift] Starting recover with wrong PIN (guess 1)")
        do {
            let secret = try await client.recover(pin: "4321".data(using: .utf8)!)
            fatalError("[Swift] Unexpected result from recover: \(String(data: secret, encoding: .utf8)!)")
        } catch RecoverError.unsuccessful {
            print("[Swift] Recover expectedly unsuccessful")
        }

        print("[Swift] Starting recover with correct PIN (guess 2)")
        do {
            let secret = try await client.recover(pin: "1234".data(using: .utf8)!)
            print("[Swift] Recovered secret: \(String(data: secret, encoding: .utf8)!)")
        } catch RecoverError.unsuccessful {
            fatalError("[Swift] Recover unexpectedly failed")
        }

        print("[Swift] Starting recover with wrong PIN (guess 1)")
        do {
            let secret = try await client.recover(pin: "4321".data(using: .utf8)!)
            fatalError("[Swift] Unexpected result from recover: \(String(data: secret, encoding: .utf8)!)")
        } catch RecoverError.unsuccessful {
            print("[Swift] Recover expectedly unsuccessful")
        }

        print("[Swift] Starting recover with wrong PIN (guess 2)")
        do {
            let secret = try await client.recover(pin: "4321".data(using: .utf8)!)
            fatalError("[Swift] Unexpected result from recover: \(String(data: secret, encoding: .utf8)!)")
        } catch RecoverError.unsuccessful {
            print("[Swift] Recover expectedly unsuccessful")
        }

        print("[Swift] Starting recover with correct PIN (guess 3)")
        do {
            let secret = try await client.recover(pin: "1234".data(using: .utf8)!)
            fatalError("[Swift] Unexpected result from recover: \(String(data: secret, encoding: .utf8)!)")
        } catch RecoverError.unsuccessful {
            print("[Swift] Recover expectedly unsuccessful")
        }

        print("[Swift] Starting register (allowing 2 guesses)")
        do {
            try await client.register(
                pin: "1234".data(using: .utf8)!,
                secret: "artemis".data(using: .utf8)!,
                guesses: 2
            )
        } catch let error {
            fatalError("[Swift] Register failed \(error)")
        }
        print("[Swift] Register succeeded")

        print("[Swift] Starting recover with wrong PIN (guess 1)")
        do {
            let secret = try await client.recover(pin: "4321".data(using: .utf8)!)
            fatalError("[Swift] Unexpected result from recover: \(String(data: secret, encoding: .utf8)!)")
        } catch RecoverError.unsuccessful {
            print("[Swift] Recover expectedly unsuccessful")
        }

        print("[Swift] Starting recover with correct PIN (guess 2)")
        do {
            let secret = try await client.recover(pin: "1234".data(using: .utf8)!)
            print("[Swift] Recovered secret: \(String(data: secret, encoding: .utf8)!)")
        } catch RecoverError.unsuccessful {
            fatalError("[Swift] Recover unexpectedly failed")
        }

        print("[Swift] Deleting secret")
        do {
            try await client.deleteAll()
        } catch let error as DeleteError {
            fatalError("[Swift] Delete unexpectedly failed \(error)")
        }
        print("[Swift] Delete succeeded")

        print("[Swift] Starting recover with correct PIN after delete")
        do {
            let secret = try await client.recover(pin: "1234".data(using: .utf8)!)
            fatalError("[Swift] Unexpected result from recover: \(String(data: secret, encoding: .utf8)!)")
        } catch RecoverError.unsuccessful {
            print("[Swift] Recover expectedly unsuccessful")
        }
    }
    // swiftlint:enable cyclomatic_complexity
}

let jsonDecoder: JSONDecoder = {
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    decoder.dataDecodingStrategy = .custom { decoder in
        let container = try decoder.singleValueContainer()
        let array = try container.decode([UInt8].self)
        return .init(array)
    }
    return decoder
}()

extension Configuration: ExpressibleByArgument, Decodable {
    public init?(argument: String) {
        guard let configuration = try? jsonDecoder.decode(Self.self, from: argument.data(using: .utf8)!) else {
            return nil
        }
        self = configuration
    }

    enum CodingKeys: String, CodingKey {
        case realms
        case registerThreshold
        case recoverThreshold
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            realms: try container.decode([Configuration.Realm].self, forKey: .realms),
            registerThreshold: try container.decode(UInt8.self, forKey: .registerThreshold),
            recoverThreshold: try container.decode(UInt8.self, forKey: .recoverThreshold)
        )
    }
}

extension Configuration.Realm: Decodable {
    enum CodingKeys: String, CodingKey {
        case id
        case address
        case publicKey
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let rawId = try container.decode([UInt8].self, forKey: .id)
        self.init(
            id: rawId.withUnsafeBufferPointer { NSUUID(uuidBytes: $0.baseAddress!) as UUID },
            address: try container.decode(URL.self, forKey: .address),
            publicKey: try container.decode(Data.self, forKey: .publicKey)
        )
    }
}

extension URL: ExpressibleByArgument {
    public init?(argument: String) {
        self.init(string: argument)
    }
}
