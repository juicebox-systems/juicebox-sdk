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

    /// Vend a new token for the specified realmId and secretId.
    public func vend(realmId: RealmId, secretId: SecretId) -> AuthToken {
        AuthToken(ffi:
            realmId.withUnsafeFfi { realmIdFfi in
                secretId.withUnsafeFfi { secretIdFfi in
                    juicebox_auth_token_generator_vend(
                        opaque,
                        JuiceboxAuthTokenParameters(
                            realm_id: realmIdFfi,
                            secret_id: secretIdFfi
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
