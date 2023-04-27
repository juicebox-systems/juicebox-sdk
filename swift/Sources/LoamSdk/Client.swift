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
import LoamSdkFfi

/// Register and recover PIN-protected secrets on behalf of a particular user.
public class Client {
    let configuration: Configuration
    let previousConfigurations: [Configuration]
    let authToken: String

    #if !os(Linux)
    /// The file path of any certificate files you wish to pin realm connections against.
    ///
    /// If no paths are provided, connection to realms will be permited as long as they are
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
        - authToken: Represents the authority to act as a particular user
            and should be valid for the lifetime of the `Client`.
     */
    public init(
        configuration: Configuration,
        previousConfigurations: [Configuration] = [],
        authToken: String
    ) {
        self.configuration = configuration
        self.previousConfigurations = previousConfigurations
        self.authToken = authToken

        self.opaque = configuration.withUnsafeFfi({ ffiConfig in
            authToken.withCString { authTokenCString in
                previousConfigurations.withUnsafeFfiPointer { previousConfigurationsBuffer in
                    loam_client_create(
                        ffiConfig,
                        .init(
                            data: previousConfigurationsBuffer,
                            length: previousConfigurations.count
                        ),
                        authTokenCString,
                        httpSend
                    )
                }
            }
        })
    }

    deinit {
        loam_client_destroy(opaque)
    }

    /**
     Stores a new PIN-protected secret on the configured realms.

     - Parameters:
        - pin: A user provided PIN. If using a strong `PinHashingMode`, this can
            safely be a low-entropy value.
        - secret: A user provided secret.
        - guesses: The number of guesses allowed before the secret can no longer
            be accessed.

     - Warning: If the secrets vary in length (such as passwords), the caller should
            add padding to obscure the secrets' length.

     - Throws: `RegisterError` if registration could not be completed successfully.
     */
    public func register(pin: Data, secret: Data, guesses: UInt16) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            pin.withLoamUnmanagedDataArray { pinArray in
                secret.withLoamUnmanagedDataArray { secretArray in
                    loam_client_register(
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
            pin.withLoamUnmanagedDataArray { pinArray in
                loam_client_recover(
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
     Deletes all secrets for this user.

     - Note: This does not delete the user's audit log.

     - Throws: `DeleteError` if deletion could not be completed successfully.
     */
    public func deleteAll() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            loam_client_delete_all(
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

let httpSend: LoamHttpSendFn = { context, requestPointer, responseCallback in
    guard let responseCallback = responseCallback else { return }
    guard let requestPointer = requestPointer else {
        responseCallback(context, nil)
        return
    }

    let requestId = requestPointer.pointee.id

    httpSession.dataTask(
        with: URLRequest(loam: requestPointer.pointee)
    ) { responseData, response, _ in
        guard let response = response as? HTTPURLResponse, let responseData = responseData else {
            responseCallback(context, nil)
            return
        }

        let responseHeaderFields = (response.allHeaderFields as? [String: Any])?
            .compactMapValues { $0 as? String } ?? [:]

        func withHeadersRecursively(
            iterator: Dictionary<String, String>.Iterator? = nil,
            body: (inout [LoamHttpHeader]) -> Void
        ) {
            var iterator = iterator ?? responseHeaderFields.makeIterator()
            if let (name, value) = iterator.next() {
                name.withCString { nameCString in
                    value.withCString { valueCString in
                        withHeadersRecursively(iterator: iterator, body: { headers in
                            headers.append(LoamHttpHeader(name: nameCString, value: valueCString))
                            body(&headers)
                        })
                    }
                }
            } else {
                var emptyHeaders = [LoamHttpHeader]()
                body(&emptyHeaders)
            }
        }

        withHeadersRecursively { headers in
            headers.withUnsafeBufferPointer { headersBuffer in
                responseData.withLoamUnmanagedDataArray { bodyArray in
                    let response = LoamHttpResponse(
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
