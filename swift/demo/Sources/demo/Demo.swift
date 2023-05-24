import ArgumentParser
import LoamSdk
import Foundation

@main
struct Demo: AsyncParsableCommand {
    @Option(name: .shortAndLong, help: "The configuration for the client SDK, in JSON format")
    var configuration: Configuration

    @Option(
        name: .shortAndLong,
        help: "The auth tokens for the client SDK, as a JSON string mapping realm ID to base64-encoded JWT"
    )
    var authTokens: [UUID: String]

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
        } catch RecoverError.invalidPin(let guessesRemaining) {
            assert(guessesRemaining == 1)
            print("[Swift] Recover expectedly unsuccessful")
        }

        print("[Swift] Starting recover with correct PIN (guess 2)")
        do {
            let secret = try await client.recover(pin: "1234".data(using: .utf8)!)
            print("[Swift] Recovered secret: \(String(data: secret, encoding: .utf8)!)")
        } catch RecoverError.invalidPin {
            fatalError("[Swift] Recover unexpectedly failed")
        }

        print("[Swift] Starting recover with wrong PIN (guess 1)")
        do {
            let secret = try await client.recover(pin: "4321".data(using: .utf8)!)
            fatalError("[Swift] Unexpected result from recover: \(String(data: secret, encoding: .utf8)!)")
        } catch RecoverError.invalidPin(let guessesRemaining) {
            assert(guessesRemaining == 1)
            print("[Swift] Recover expectedly unsuccessful")
        }

        print("[Swift] Starting recover with wrong PIN (guess 2)")
        do {
            let secret = try await client.recover(pin: "4321".data(using: .utf8)!)
            fatalError("[Swift] Unexpected result from recover: \(String(data: secret, encoding: .utf8)!)")
        } catch RecoverError.invalidPin(let guessesRemaining) {
            assert(guessesRemaining == 0)
            print("[Swift] Recover expectedly unsuccessful")
        }

        print("[Swift] Starting recover with correct PIN (guess 3)")
        do {
            let secret = try await client.recover(pin: "1234".data(using: .utf8)!)
            fatalError("[Swift] Unexpected result from recover: \(String(data: secret, encoding: .utf8)!)")
        } catch RecoverError.invalidPin(let guessesRemaining) {
            assert(guessesRemaining == 0)
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
        } catch RecoverError.invalidPin(let guessesRemaining) {
            assert(guessesRemaining == 1)
            print("[Swift] Recover expectedly unsuccessful")
        }

        print("[Swift] Starting recover with correct PIN (guess 2)")
        do {
            let secret = try await client.recover(pin: "1234".data(using: .utf8)!)
            print("[Swift] Recovered secret: \(String(data: secret, encoding: .utf8)!)")
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
            let secret = try await client.recover(pin: "1234".data(using: .utf8)!)
            fatalError("[Swift] Unexpected result from recover: \(String(data: secret, encoding: .utf8)!)")
        } catch RecoverError.notRegistered {
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

extension Dictionary: ExpressibleByArgument where Key == UUID, Value == String {
    enum ArgumentError: Error {
        case invalidRealmId
    }

    public init?(argument: String) {
        guard let dictionary = try? jsonDecoder.decode([String: String].self, from: argument.data(using: .utf8)!) else {
            return nil
        }
        guard let keysWithValues = try? dictionary.map({ key, value in
            guard let rawId = Data(hexString: key) else { throw ArgumentError.invalidRealmId }
            return (rawId.withUnsafeBytes { NSUUID(uuidBytes: $0.baseAddress!) as UUID }, value)
        }) else { return nil }
        self = Dictionary(uniqueKeysWithValues: keysWithValues)
    }
}

extension Data {
    init?(hexString: String) {
        guard hexString.count.isMultiple(of: 2) else {
            return nil
        }

        let characters = hexString.map { $0 }
        let bytes = stride(from: 0, to: characters.count, by: 2)
            .map { String(characters[$0]) + String(characters[$0 + 1]) }
            .compactMap { UInt8($0, radix: 16) }

        guard hexString.count / bytes.count == 2 else { return nil }

        self.init(bytes)
    }
}

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
        case pinHashingMode
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            realms: try container.decode([Configuration.Realm].self, forKey: .realms),
            registerThreshold: try container.decode(UInt8.self, forKey: .registerThreshold),
            recoverThreshold: try container.decode(UInt8.self, forKey: .recoverThreshold),
            pinHashingMode: PinHashingMode(rawValue: try container.decode(UInt32.self, forKey: .pinHashingMode))!
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
            publicKey: try container.decodeIfPresent(Data.self, forKey: .publicKey)
        )
    }
}

extension URL: ExpressibleByArgument {
    public init?(argument: String) {
        self.init(string: argument)
    }
}
