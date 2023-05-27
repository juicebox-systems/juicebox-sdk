//
//  RealmId.swift
//  
//
//  Created by Nora Trapp on 5/26/23.
//

import Foundation

public struct RealmId {
    // swiftlint:disable:next large_tuple
    typealias RawRealmId = (
        UInt8,
        UInt8,
        UInt8,
        UInt8,
        UInt8,
        UInt8,
        UInt8,
        UInt8,
        UInt8,
        UInt8,
        UInt8,
        UInt8,
        UInt8,
        UInt8,
        UInt8,
        UInt8
    )

    let raw: RawRealmId

    init(raw: RawRealmId) {
        self.raw = raw
    }

    public init?(string: String) {
        let string = string.replacingOccurrences(of: "-", with: "")

        guard string.count == 32 else {
            return nil
        }

        let characters = string.map { $0 }
        let bytes = stride(from: 0, to: characters.count, by: 2)
            .map { String(characters[$0]) + String(characters[$0 + 1]) }
            .compactMap { UInt8($0, radix: 16) }

        self.init(bytes: bytes)
    }

    public init?(bytes: [UInt8]) {
        guard bytes.count == 16 else { return nil }

        self.raw = (
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15]
        )
    }
}

extension RealmId: Equatable, Hashable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        return lhs.raw.0 == rhs.raw.0 &&
        lhs.raw.1 == rhs.raw.1 &&
        lhs.raw.2 == rhs.raw.2 &&
        lhs.raw.3 == rhs.raw.3 &&
        lhs.raw.4 == rhs.raw.4 &&
        lhs.raw.5 == rhs.raw.5 &&
        lhs.raw.6 == rhs.raw.6 &&
        lhs.raw.7 == rhs.raw.7 &&
        lhs.raw.8 == rhs.raw.8 &&
        lhs.raw.9 == rhs.raw.9 &&
        lhs.raw.10 == rhs.raw.10 &&
        lhs.raw.11 == rhs.raw.11 &&
        lhs.raw.12 == rhs.raw.12 &&
        lhs.raw.13 == rhs.raw.13 &&
        lhs.raw.14 == rhs.raw.14 &&
        lhs.raw.15 == rhs.raw.15
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(raw.0)
        hasher.combine(raw.1)
        hasher.combine(raw.2)
        hasher.combine(raw.3)
        hasher.combine(raw.4)
        hasher.combine(raw.5)
        hasher.combine(raw.6)
        hasher.combine(raw.7)
        hasher.combine(raw.8)
        hasher.combine(raw.9)
        hasher.combine(raw.10)
        hasher.combine(raw.11)
        hasher.combine(raw.12)
        hasher.combine(raw.13)
        hasher.combine(raw.14)
        hasher.combine(raw.15)
    }
}

extension RealmId: Decodable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let string = try container.decode(String.self)

        guard let realmId = RealmId(string: string) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid RealmId string")
        }

        self = realmId
    }
}
