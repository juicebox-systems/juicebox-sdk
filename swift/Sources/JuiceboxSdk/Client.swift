//
//  Client.swift
//
//
//  Created by Nora Trapp on 3/29/23.
//

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import JuiceboxSdkFfi

/// Register and recover PIN-protected secrets on behalf of a particular user.
public class Client {
    public let configuration: Configuration
    public let previousConfigurations: [Configuration]

    /// Called when any client requires an auth token for a given realm. In general,
    /// it's recommended you maintain some form of cache for tokens and do not fetch
    /// a fresh token for every request. Said cache should be invalidated if any operation
    /// returns an `InvalidAuth` error.
    public static var fetchAuthTokenCallback: ((_ realmId: UUID) -> String?)?

    #if !os(Linux)
    /// The file path of any certificate files you wish to pin realm connections against.
    ///
    /// If no paths are provided, connection to realms will be permitted as long as they are
    /// using a certificate issued by a trusted authority.
    ///
    /// - Note: Certificates should be provided in DER format.
    public static var pinnedCertificatePaths: [URL]?
    #endif

    private let opaque: OpaquePointer

    /**
     Initializes a new client with the provided configuration and auth token.

     - Parameters:
        - configuration: Represents the current configuration. The configuration
            provided must include at least one `Realm`.
        - previousConfigurations: Represents any other configurations you have
            previously registered with that you may not yet have migrated the data from.
            During `recover`, they will be tried if the current user has not yet registered
            on the current configuration. These should be ordered from most recently to least
            recently used.
        - authTokens: Represents the authority to act as a particular user on a particular
            realm and should be valid for the lifetime of the `Client`. Alternatively, you
            may omit this argument and implement `Client.fetchAuthTokenCallback`
            to fetch and refresh tokens as needed.
     */
    public init(
        configuration: Configuration,
        authTokens: [UUID: String]? = nil,
        previousConfigurations: [Configuration] = []
    ) {
        self.configuration = configuration
        self.previousConfigurations = previousConfigurations

        self.opaque = configuration.withUnsafeFfi({ ffiConfig in
            previousConfigurations.withUnsafeFfiPointer { previousConfigurationsBuffer in
                juicebox_client_create(
                    ffiConfig,
                    .init(
                        data: previousConfigurationsBuffer,
                        length: previousConfigurations.count
                    ),
                    authTokenGet,
                    httpSend
                )
            }
        })

        if let authTokens = authTokens {
            Self.fetchAuthTokenCallback = { authTokens[$0] }
        } else {
            assert(Self.fetchAuthTokenCallback != nil)
        }
    }

    deinit {
        juicebox_client_destroy(opaque)
    }

    /**
     Stores a new PIN-protected secret on the configured realms.

     - Parameters:
        - pin: A user provided PIN. If using a strong `PinHashingMode`, this can
            safely be a low-entropy value.
        - secret: A user provided secret with a maximum length of 128-bytes.
        - guesses: The number of guesses allowed before the secret can no longer
            be accessed.

     - Throws: `RegisterError` if registration could not be completed successfully.
     */
    public func register(pin: Data, secret: Data, guesses: UInt16) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            pin.withJuiceboxUnmanagedDataArray { pinArray in
                secret.withJuiceboxUnmanagedDataArray { secretArray in
                    juicebox_client_register(
                        opaque,
                        Unmanaged.passRetained(Box(continuation)).toOpaque(),
                        pinArray,
                        secretArray,
                        guesses
                    ) { context, error in
                        guard let context = context else { fatalError() }
                        let box: Box<CheckedContinuation<Void, Error>>
                            = Unmanaged.fromOpaque(context).takeRetainedValue()
                        if let error = error?.pointee {
                            box.value.resume(throwing: RegisterError(error))
                        } else {
                            box.value.resume(returning: ())
                        }
                    }
                }
            }
        }
    }

    /**
     Retrieves a PIN-protected secret from the configured realms, or falls back to the
     previous realms if the current realms do not have any secret registered.

     - Parameters:
        - pin: A user provided PIN. If using a strong `PinHashingMode`, this can
            safely be a low-entropy value.

     - Returns: The recovered user provided secret.

     - Throws: `RecoverError` if recovery could not be completed successfully.
     */
    public func recover(pin: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            pin.withJuiceboxUnmanagedDataArray { pinArray in
                juicebox_client_recover(
                    opaque,
                    Unmanaged.passRetained(Box(continuation)).toOpaque(),
                    pinArray
                ) { context, secretBuffer, error in
                    guard let context = context else { fatalError() }
                    let box: Box<CheckedContinuation<Data, Error>> = Unmanaged.fromOpaque(context).takeRetainedValue()
                    if let error = error?.pointee {
                        box.value.resume(throwing: RecoverError(error))
                    } else if let secret = Data(secretBuffer) {
                        box.value.resume(returning: secret)
                    } else {
                        box.value.resume(throwing: RecoverError.assertion)
                    }
                }
            }
        }
    }

    /**
     Deletes the registered secret for this user, if any.

     - Throws: `DeleteError` if deletion could not be completed successfully.
     */
    public func delete() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            juicebox_client_delete(
                opaque,
                Unmanaged.passRetained(Box(continuation)).toOpaque()
            ) { context, error in
                guard let context = context else { fatalError() }
                let box: Box<CheckedContinuation<Void, Error>> = Unmanaged.fromOpaque(context).takeRetainedValue()
                if let error = error?.pointee {
                    box.value.resume(throwing: DeleteError(error))
                } else {
                    box.value.resume(returning: ())
                }
            }
        }
    }
}

private let httpSession = URLSession(
    configuration: .ephemeral,
    delegate: TLSSessionPinningDelegate(),
    delegateQueue: .main
)

let httpSend: JuiceboxHttpSendFn = { context, requestPointer, responseCallback in
    guard let responseCallback = responseCallback else { return }
    guard let requestPointer = requestPointer else {
        responseCallback(context, nil)
        return
    }

    let requestId = requestPointer.pointee.id

    httpSession.dataTask(
        with: URLRequest(juicebox: requestPointer.pointee)
    ) { responseData, response, _ in
        guard let response = response as? HTTPURLResponse, let responseData = responseData else {
            responseCallback(context, nil)
            return
        }

        let responseHeaderFields = (response.allHeaderFields as? [String: Any])?
            .compactMapValues { $0 as? String } ?? [:]

        func withHeadersRecursively(
            iterator: Dictionary<String, String>.Iterator? = nil,
            body: (inout [JuiceboxHttpHeader]) -> Void
        ) {
            var iterator = iterator ?? responseHeaderFields.makeIterator()
            if let (name, value) = iterator.next() {
                name.withCString { nameCString in
                    value.withCString { valueCString in
                        withHeadersRecursively(iterator: iterator, body: { headers in
                            headers.append(JuiceboxHttpHeader(name: nameCString, value: valueCString))
                            body(&headers)
                        })
                    }
                }
            } else {
                var emptyHeaders = [JuiceboxHttpHeader]()
                body(&emptyHeaders)
            }
        }

        withHeadersRecursively { headers in
            headers.withUnsafeBufferPointer { headersBuffer in
                responseData.withJuiceboxUnmanagedDataArray { bodyArray in
                    let response = JuiceboxHttpResponse(
                        id: requestId,
                        status_code: UInt16(response.statusCode),
                        headers: .init(data: headersBuffer.baseAddress, length: headersBuffer.count),
                        body: bodyArray
                    )
                    withUnsafePointer(to: response) {
                        responseCallback(context, $0)
                    }
                }
            }
        }
    }.resume()
}

let authTokenGet: JuiceboxAuthTokenGetFn = { context, contextId, realmId, callback -> Void in
    guard let callback = callback, let realmId = realmId else { return }

    guard let fetchFn = Client.fetchAuthTokenCallback else {
        callback(context, contextId, nil)
        return
    }

    if let authToken = fetchFn(UUID(uuid: realmId.pointee)) {
        authToken.withCString { authTokenCString in
            callback(context, contextId, authTokenCString)
        }
    } else {
        callback(context, contextId, nil)
    }
}

private class TLSSessionPinningDelegate: NSObject, URLSessionDelegate {
    #if !os(Linux)
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?
        ) -> Void) {
        var disposition: URLSession.AuthChallengeDisposition = .performDefaultHandling
        var credential: URLCredential?

        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let serverTrust = challenge.protectionSpace.serverTrust {
            if evaluateServerTrust(serverTrust, forDomain: challenge.protectionSpace.host) {
                credential = URLCredential(trust: serverTrust)
                disposition = .useCredential
            } else {
                disposition = .cancelAuthenticationChallenge
            }
        } else {
            disposition = .performDefaultHandling
        }

        completionHandler(disposition, credential)
    }

    func evaluateServerTrust(_ serverTrust: SecTrust, forDomain domain: String) -> Bool {
        let policy = SecPolicyCreateSSL(true, domain as CFString)
        guard SecTrustSetPolicies(serverTrust, policy) == errSecSuccess else {
            return false
        }

        if let pinnedCertificatePaths = Client.pinnedCertificatePaths, !pinnedCertificatePaths.isEmpty {
            let pinnedCertificates = pinnedCertificatePaths
                .lazy
                .compactMap { try? Data(contentsOf: $0) }
                .map { SecCertificateCreateWithData(nil, $0 as CFData) }

            guard SecTrustSetAnchorCertificates(
                serverTrust,
                Array(pinnedCertificates) as CFArray
            ) == errSecSuccess else {
                return false
            }
        }

        return SecTrustEvaluateWithError(serverTrust, nil)
    }
    #endif
}

private class Box<T> {
    let value: T

    init(_ value: T) {
        self.value = value
    }
}
