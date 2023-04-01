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

        func withUnsafeFfi<Result>(_ body: (LoamRealm) throws -> Result) rethrows -> Result {
            try address.absoluteString.withCString { addressCStr in
                try publicKey.withLoamUnownedDataBuffer { publicKeyBuffer in
                    try body(.init(
                        id: id.uuid,
                        address: addressCStr,
                        public_key: publicKeyBuffer
                    ))
                }
            }
        }
    }
    public let realms: [Realm]
    public let registerThreshold: UInt8
    public let recoverThreshold: UInt8

    func withUnsafeFfi<Result>(_ body: (LoamConfiguration) throws -> Result) rethrows -> Result {
        try realms.withUnsafeFfiPointer { realmsBuffer in
            try body(.init(
                realms: .init(data: realmsBuffer, length: realms.count),
                register_threshold: registerThreshold,
                recover_threshold: recoverThreshold
            ))
        }
    }
}

extension Array where Element == Configuration.Realm {
    func withUnsafeFfiPointer<Result>(_ body: (UnsafePointer<LoamRealm>) throws -> Result) rethrows -> Result {
        func withRealmsRecursively(
            iterator: IndexingIterator<[Configuration.Realm]>? = nil,
            body: (inout [LoamRealm]) throws -> Result
        ) rethrows -> Result {
            var iterator = iterator ?? makeIterator()
            if let realm = iterator.next() {
                return try realm.withUnsafeFfi { ffiRealm in
                    try withRealmsRecursively(iterator: iterator, body: { ffiRealms in
                        ffiRealms.append(ffiRealm)
                        return try body(&ffiRealms)
                    })
                }
            } else {
                var emptyRealms = [LoamRealm]()
                return try body(&emptyRealms)
            }
        }

        return try withRealmsRecursively {
            try $0.withUnsafeBufferPointer {
                try body($0.baseAddress!)
            }
        }
    }
}
