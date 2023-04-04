//
//  Extensions.swift
//  
//
//  Created by Nora Trapp on 4/1/23.
//

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import LoamSdkFfi

extension LoamClientCreateError: Error {}
extension LoamRegisterError: Error {}
extension LoamRecoverError: Error {}
extension LoamDeleteError: Error {}

extension Data {
    func withLoamUnmanagedDataBuffer<Result>(_ body: (LoamUnmanagedDataBuffer) throws -> Result) rethrows -> Result {
        try withUnsafeBytes { bytes in
            try body(.init(
                data: bytes.bindMemory(to: UInt8.self).baseAddress,
                length: bytes.count
            ))
        }
    }

    init?(_ buffer: LoamUnmanagedDataBuffer) {
        guard let data = buffer.data else { return nil }
        self.init(bytes: data, count: buffer.length)
    }
}

extension URLRequest {
    init(loam: LoamHttpRequest) {
        self.init(url: URL(string: String(cString: loam.url))!)
        switch loam.method {
        case LoamHttpRequestMethodGet:
            self.httpMethod = "GET"
        case LoamHttpRequestMethodPut:
            self.httpMethod = "PUT"
        case LoamHttpRequestMethodDelete:
            self.httpMethod = "DELETE"
        case LoamHttpRequestMethodPost:
            self.httpMethod = "POST"
        default:
            break
        }

        if let headers = loam.headers.data {
            Array(UnsafeBufferPointer(start: headers, count: loam.headers.length)).map {
                (String(cString: $0.name), String(cString: $0.value))
            }.forEach { name, value in
                setValue(value, forHTTPHeaderField: name)
            }
        }

        httpBody = .init(loam.body)
    }
}
