//
//  Configuration.swift
//
//
//  Created by Nora Trapp on 3/29/23.
//

import Foundation
import JuiceboxSdkFfi

/// The parameters used to configure a `Client`.
public struct Configuration {
    /// A remote service that the client interacts with directly.
    public struct Realm {
        /// A unique identifier specified by the realm.
        public let id: RealmId
        /// The network address to connect to the service.
        public let address: URL
        /// A long-lived public key for which a hardware backed service
        /// maintains a matching private key. Software realms do not
        /// require public keys.
        public let publicKey: Data?

        public init(id: RealmId, address: URL, publicKey: Data? = nil) {
            self.id = id
            self.address = address
            self.publicKey = publicKey
        }
    }

    /// The remote services that the client interacts with.
    ///
    /// There must be between `registerThreshold` and 255 realms, inclusive.
    public let realms: [Realm]

    /// A registration will be considered successful if it's successful on at
    /// least this many realms.
    ///
    /// Must be between `recoverThreshold` and `realms.count`, inclusive.
    public let registerThreshold: UInt8

    /// A recovery (or an adversary) will need the cooperation of this many
    /// realms to retrieve the secret.
    ///
    /// Must be between `ceil(realms.count / 2)` and `realms.count`, inclusive.
    public let recoverThreshold: UInt8

    /// A strategy for hashing the user provided pin.
    public enum PinHashingMode: UInt32 {
        /// A tuned hash, secure for use on modern devices as of 2019 with low-entropy PINs.
        case standard2019 = 0
        /// A fast hash used for testing. Do not use in production.
        case fastInsecure = 1

        public init?(stringValue: String) {
            switch stringValue {
            case "Standard2019": self = .standard2019
            case "FastInsecure": self = .fastInsecure
            default: return nil
            }
        }
    }

    /// Defines how the provided PIN will be hashed before register and recover
    /// operations. Changing modes will make previous secrets stored on the realms
    /// inaccessible with the same PIN and should not be done without re-registering
    /// secrets.
    public let pinHashingMode: PinHashingMode

    public init(realms: [Realm], registerThreshold: UInt8, recoverThreshold: UInt8, pinHashingMode: PinHashingMode) {
        self.realms = realms
        self.registerThreshold = registerThreshold
        self.recoverThreshold = recoverThreshold
        self.pinHashingMode = pinHashingMode
    }

    public init?(json: String) {
        guard let jsonData = json.data(using: .utf8) else { return nil }

        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        decoder.dataDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let string = try container.decode(String.self)
            guard let data = Data(hexString: string) else {
                throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid data string")
            }
            return data
        }

        guard let configuration = try? decoder.decode(Self.self, from: jsonData) else {
            return nil
        }

        self = configuration
    }
}

protocol FfiConvertible {
    associatedtype FfiType

    func withUnsafeFfi<Result>(_ body: (FfiType) throws -> Result) rethrows -> Result
}

extension Configuration: FfiConvertible {
    typealias FfiType = JuiceboxConfiguration

    func withUnsafeFfi<Result>(_ body: (FfiType) throws -> Result) rethrows -> Result {
        try realms.withUnsafeFfiPointer { realmsBuffer in
            try body(.init(
                realms: .init(data: realmsBuffer, length: realms.count),
                register_threshold: registerThreshold,
                recover_threshold: recoverThreshold,
                pin_hashing_mode: JuiceboxPinHashingMode(rawValue: pinHashingMode.rawValue)
            ))
        }
    }
}

extension Configuration.Realm: FfiConvertible {
    typealias FfiType = JuiceboxRealm

    func withUnsafeFfi<Result>(_ body: (FfiType) throws -> Result) rethrows -> Result {
        try address.absoluteString.withCString { addressCStr in
            if let publicKey = publicKey {
                return try publicKey.withJuiceboxUnmanagedDataArray { publicKeyArray in
                    try withUnsafePointer(to: publicKeyArray) { publicKeyArrayPointer in
                        try body(.init(
                            id: id.raw,
                            address: addressCStr,
                            public_key: publicKeyArrayPointer
                        ))
                    }
                }
            } else {
                return try body(.init(
                    id: id.raw,
                    address: addressCStr,
                    public_key: nil
                ))
            }

        }
    }
}

extension Array where Element: FfiConvertible {
    func withUnsafeFfiPointer<Result>(_ body: (UnsafePointer<Element.FfiType>) throws -> Result) rethrows -> Result {
        func withElementsRecursively(
            iterator: IndexingIterator<[Element]>? = nil,
            body: (inout [Element.FfiType]) throws -> Result
        ) rethrows -> Result {
            var iterator = iterator ?? makeIterator()
            if let element = iterator.next() {
                return try element.withUnsafeFfi { ffiElement in
                    try withElementsRecursively(iterator: iterator, body: { ffiElements in
                        ffiElements.append(ffiElement)
                        return try body(&ffiElements)
                    })
                }
            } else {
                var empty = [Element.FfiType]()
                return try body(&empty)
            }
        }

        return try withElementsRecursively {
            try $0.withUnsafeBufferPointer {
                try body($0.baseAddress!)
            }
        }
    }
}

extension Configuration: Decodable {
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
            pinHashingMode: PinHashingMode(stringValue: try container.decode(String.self, forKey: .pinHashingMode))!
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
        self.init(
            id: try container.decode(RealmId.self, forKey: .id),
            address: try container.decode(URL.self, forKey: .address),
            publicKey: try container.decodeIfPresent(Data.self, forKey: .publicKey)
        )
    }
}
