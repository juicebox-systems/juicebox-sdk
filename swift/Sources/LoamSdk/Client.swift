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

public class Client {
    public let configuration: Configuration
    public let authToken: AuthToken

    private let opaque: OpaquePointer

    public init(configuration: Configuration, authToken: AuthToken) throws {
        self.configuration = configuration
        self.authToken = authToken

        var error = LoamClientCreateErrorNone
        guard let opaque = configuration.withUnsafeFfi({ ffiConfig in
            authToken.withUnsafeFfi { ffiToken in
                loam_client_create(ffiConfig, ffiToken, httpSend, &error)
            }
        }), error == LoamClientCreateErrorNone else {
            throw error
        }

        self.opaque = opaque
    }

    deinit {
        loam_client_destroy(opaque)
    }

    func register(pin: Data, secret: Data, guesses: UInt16) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            pin.withLoamUnmanagedDataBuffer { pinBuffer in
                secret.withLoamUnmanagedDataBuffer { secretBuffer in
                    loam_client_register(
                        opaque,
                        Unmanaged.passRetained(Box(continuation)).toOpaque(),
                        pinBuffer,
                        secretBuffer,
                        guesses
                    ) { context, error in
                        guard let context = context else { fatalError() }
                        let box: Box<CheckedContinuation<Void, Error>>
                            = Unmanaged.fromOpaque(context).takeRetainedValue()
                        if let error = error?.pointee {
                            box.value.resume(throwing: error)
                        } else {
                            box.value.resume(returning: ())
                        }
                    }
                }
            }
        }
    }

    func recover(pin: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            pin.withLoamUnmanagedDataBuffer { pinBuffer in
                loam_client_recover(
                    opaque,
                    Unmanaged.passRetained(Box(continuation)).toOpaque(),
                    pinBuffer
                ) { context, secretBuffer, error in
                    guard let context = context else { fatalError() }
                    let box: Box<CheckedContinuation<Data, Error>> = Unmanaged.fromOpaque(context).takeRetainedValue()
                    if let error = error?.pointee {
                        box.value.resume(throwing: error)
                    } else if let secret = Data(secretBuffer) {
                        box.value.resume(returning: secret)
                    } else {
                        box.value.resume(throwing: LoamRecoverErrorUnsuccessful)
                    }
                }
            }
        }
    }

    func deleteAll() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            loam_client_delete_all(
                opaque,
                Unmanaged.passRetained(Box(continuation)).toOpaque()
            ) { context, error in
                guard let context = context else { fatalError() }
                let box: Box<CheckedContinuation<Void, Error>> = Unmanaged.fromOpaque(context).takeRetainedValue()
                if let error = error?.pointee {
                    box.value.resume(throwing: error)
                } else {
                    box.value.resume(returning: ())
                }
            }
        }
    }
}

let httpSend: LoamHttpSendFn = { context, requestPointer, responseCallback in
    guard let responseCallback = responseCallback else { return }
    guard let requestPointer = requestPointer else {
        responseCallback(context, nil)
        return
    }
    URLSession.shared.dataTask(
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
                responseData.withLoamUnmanagedDataBuffer { bodyBuffer in
                    let response = LoamHttpResponse(
                        id: requestPointer.pointee.id,
                        status_code: UInt16(response.statusCode),
                        headers: .init(data: headersBuffer.baseAddress, length: headersBuffer.count),
                        body: bodyBuffer
                    )
                    withUnsafePointer(to: response) {
                        responseCallback(context, $0)
                    }
                }
            }
        }
    }.resume()
}

private class Box<T> {
    let value: T

    init(_ value: T) {
        self.value = value
    }
}
