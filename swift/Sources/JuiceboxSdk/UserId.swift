//
//  UserId.swift
//
//
//  Created by Nora Trapp on 10/5/23.
//

import Foundation

public struct UserId: Identifable {
    public let raw: Raw

    public init(raw: Raw) {
        self.raw = raw
    }

    /// Generate a new random UserId
    public static func random() -> Self {
        return UserId(raw: UUID().uuid)
    }
}

extension UserId: FfiConvertible {
    func withUnsafeFfi<Result>(_ body: (Raw) throws -> Result) rethrows -> Result {
        try body(raw)
    }
}
