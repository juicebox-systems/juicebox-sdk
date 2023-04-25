//
//  Configuration.swift
//  
//
//  Created by Nora Trapp on 3/29/23.
//

import Foundation
import LoamSdkFfi

public struct Configuration {
    public struct Realm {
        public let id: UUID
        public let address: URL
        public let publicKey: Data

        public init(id: UUID, address: URL, publicKey: Data) {
            self.id = id
            self.address = address
            self.publicKey = publicKey
        }
    }
    public let realms: [Realm]
    public let registerThreshold: UInt8
    public let recoverThreshold: UInt8

    public enum PinHashingMode: UInt32 {
        case none = 0
        case standard2019 = 1
        case fastInsecure = 2
    }
    public let pinHashingMode: PinHashingMode

    public init(realms: [Realm], registerThreshold: UInt8, recoverThreshold: UInt8, pinHashingMode: PinHashingMode) {
        self.realms = realms
        self.registerThreshold = registerThreshold
        self.recoverThreshold = recoverThreshold
        self.pinHashingMode = pinHashingMode
    }
}

protocol FfiConvertible {
    associatedtype FfiType

    func withUnsafeFfi<Result>(_ body: (FfiType) throws -> Result) rethrows -> Result
}

extension Configuration: FfiConvertible {
    typealias FfiType = LoamConfiguration

    func withUnsafeFfi<Result>(_ body: (FfiType) throws -> Result) rethrows -> Result {
        try realms.withUnsafeFfiPointer { realmsBuffer in
            try body(.init(
                realms: .init(data: realmsBuffer, length: realms.count),
                register_threshold: registerThreshold,
                recover_threshold: recoverThreshold,
                pin_hashing_mode: LoamPinHashingMode(rawValue: pinHashingMode.rawValue)
            ))
        }
    }
}

extension Configuration.Realm: FfiConvertible {
    typealias FfiType = LoamRealm

    func withUnsafeFfi<Result>(_ body: (FfiType) throws -> Result) rethrows -> Result {
        try address.absoluteString.withCString { addressCStr in
            try publicKey.withLoamUnmanagedDataArray { publicKeyArray in
                try body(.init(
                    id: id.uuid,
                    address: addressCStr,
                    public_key: publicKeyArray
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
