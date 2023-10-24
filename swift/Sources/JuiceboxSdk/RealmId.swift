//
//  RealmId.swift
//  
//
//  Created by Nora Trapp on 5/26/23.
//

import Foundation

public struct RealmId: Identifable {
    public let raw: Raw

    public init(raw: Raw) {
        self.raw = raw
    }
}

extension RealmId: FfiConvertible {
    func withUnsafeFfi<Result>(_ body: (Raw) throws -> Result) rethrows -> Result {
        try body(raw)
    }
}
