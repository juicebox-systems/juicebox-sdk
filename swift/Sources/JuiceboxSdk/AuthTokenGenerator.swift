//
//  AuthTokenGenerator.swift
//
//
//  Created by Nora Trapp on 10/5/23.
//

import Foundation
import JuiceboxSdkFfi

/// A generator used for vending on device tokens when a tenant
/// backend service is unavailable to vend tokens.
public final class AuthTokenGenerator {
    /**
     Initializes a new generator.

     - Parameters:
        - json: A json string representing a generator configuration.
     */
    public init(json: String) {
        self.opaque = json.withCString { jsonCStr in
            juicebox_auth_token_generator_create_from_json(jsonCStr)
        }
    }

    private let opaque: OpaquePointer

    deinit {
        juicebox_auth_token_generator_destroy(opaque)
    }

    /// Vend a new token for the specified realmId and userId.
    public func vend(realmId: RealmId, userId: UserId) -> AuthToken {
        AuthToken(ffi:
            realmId.withUnsafeFfi { realmIdBuffer in
                userId.withUnsafeFfi { userIdBuffer in
                    juicebox_auth_token_generator_vend(
                        opaque,
                        JuiceboxAuthTokenParameters(
                            realm_id: realmIdBuffer,
                            user_id: userIdBuffer
                        ))
                }
            }
        )
    }
}

extension AuthTokenGenerator: FfiConvertible {
    func withUnsafeFfi<Result>(_ body: (OpaquePointer?) throws -> Result) rethrows -> Result {
        try body(opaque)
    }
}
