//
//  Configuration.swift
//
//
//  Created by Nora Trapp on 3/29/23.
//

import Foundation
import JuiceboxSdkFfi

/// The parameters used to configure a `Client`.
public final class Configuration {
    /**
     Initializes a new configuration.

     - Parameters:
        - realms: The remote services that the client interacts with.

            There must be between `registerThreshold` and 255
            realms, inclusive.
        - registerThreshold: A registration will be considered successful if it's successful
            on at least this many realms.

            Must be between `recoverThreshold` and `realms.count`, inclusive.
        - recoverThreshold: A recovery (or an adversary) will need the cooperation of this
            many realms to retrieve the secret.

            Must be between `ceil(realms.count / 2)` and `realms.count`, inclusive.
        - pinHashingMode: Defines how the provided PIN will be hashed before register and
            recover operations. Changing modes will make previous secrets stored on the realms
            inaccessible with the same PIN and should not be done without re-registering secrets.
     */
    public init(
        realms: [Realm],
        registerThreshold: UInt32,
        recoverThreshold: UInt32,
        pinHashingMode: PinHashingMode
    ) {
        self.opaque = realms.withUnsafeFfiPointer { realmsBuffer in
            juicebox_configuration_create(
                .init(data: realmsBuffer, length: realms.count),
                registerThreshold,
                recoverThreshold,
                JuiceboxPinHashingMode(rawValue: pinHashingMode.rawValue)
            )
        }
    }

    /**
     Initializes a new configuration.

     - Parameters:
        - json: A json string representing a juicebox configuration.
     */
    public init(json: String) {
        self.opaque = json.withCString { jsonCStr in
            juicebox_configuration_create_from_json(jsonCStr)
        }
    }

    private let opaque: OpaquePointer

    deinit {
        juicebox_configuration_destroy(opaque)
    }

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

    /// A strategy for hashing the user provided pin.
    public enum PinHashingMode: UInt32 {
        /// A tuned hash, secure for use on modern devices as of 2019 with low-entropy PINs.
        case standard2019 = 0
        /// A fast hash used for testing. Do not use in production.
        case fastInsecure = 1
    }
}

extension Configuration: Equatable {
    public static func == (lhs: Configuration, rhs: Configuration) -> Bool {
        juicebox_configurations_are_equal(lhs.opaque, rhs.opaque)
    }
}

protocol FfiConvertible {
    associatedtype FfiType

    func withUnsafeFfi<Result>(_ body: (FfiType) throws -> Result) rethrows -> Result
}

extension Configuration: FfiConvertible {
    typealias FfiType = OpaquePointer?

    func withUnsafeFfi<Result>(_ body: (OpaquePointer?) throws -> Result) rethrows -> Result {
        try body(opaque)
    }
}

extension Configuration.Realm: FfiConvertible {
    typealias FfiType = JuiceboxRealm

    func withUnsafeFfi<Result>(_ body: (FfiType) throws -> Result) rethrows -> Result {
        try address.absoluteString.withCString { addressCStr in
            try id.withUnsafeFfi { rawId in
                if let publicKey = publicKey {
                    return try publicKey.withJuiceboxUnmanagedDataArray { publicKeyArray in
                        try withUnsafePointer(to: publicKeyArray) { publicKeyArrayPointer in
                            try body(.init(
                                id: rawId,
                                address: addressCStr,
                                public_key: publicKeyArrayPointer
                            ))
                        }
                    }
                } else {
                    return try body(.init(
                        id: rawId,
                        address: addressCStr,
                        public_key: nil
                    ))
                }
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
            var iterator = iterator ?? reversed().makeIterator()
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
