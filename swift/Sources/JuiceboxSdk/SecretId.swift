//
//  SecretId.swift
//
//
//  Created by Nora Trapp on 10/5/23.
//

import Foundation

/// A 16-byte unique identifier for a given secret.
public struct SecretId: Identifable {
    public let raw: Raw

    public init(raw: Raw) {
        self.raw = raw
    }

    /// Generate a new random SecretId
    public static func random() -> Self {
        return SecretId(raw: UUID().uuid)
    }
}

extension SecretId: FfiConvertible {
    func withUnsafeFfi<Result>(_ body: (Raw) throws -> Result) rethrows -> Result {
        try body(raw)
    }
}
