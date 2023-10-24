//
//  AuthToken.swift
//
//
//  Created by Nora Trapp on 10/5/23.
//

import Foundation
import JuiceboxSdkFfi

/// A token used to authenticate with a Realm
public final class AuthToken {
    /**
     Initializes a new token.

     - Parameters:
        - jwt: The JWT string vended by a tenant server.
     */
    public init(jwt: String) {
        self.opaque = jwt.withCString { jwtCStr in
            juicebox_auth_token_create(jwtCStr)
        }
    }

    init(ffi: OpaquePointer) {
        self.opaque = ffi
    }

    private let opaque: OpaquePointer

    public func string() async -> String {
        await withCheckedContinuation { continuation in
            withUnsafeFfi { ffi in
                juicebox_auth_token_string(
                    ffi,
                    Unmanaged.passRetained(Box(continuation)).toOpaque()
                ) { _, context, cString in
                    guard let context = context, let cString = cString else { fatalError() }
                    let box: Box<CheckedContinuation<String, Error>>
                        = Unmanaged.fromOpaque(context).takeRetainedValue()
                    box.value.resume(returning: String(cString: cString))
                }
            }
        }
    }

    deinit {
        juicebox_auth_token_destroy(opaque)
    }
}

extension AuthToken: FfiConvertible {
    func withUnsafeFfi<Result>(_ body: (OpaquePointer?) throws -> Result) rethrows -> Result {
        try body(opaque)
    }
}
