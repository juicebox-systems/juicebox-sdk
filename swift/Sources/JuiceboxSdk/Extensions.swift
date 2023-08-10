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
import JuiceboxSdkFfi

extension JuiceboxRegisterError: Error {}
extension JuiceboxRecoverError: Error {}
extension JuiceboxDeleteError: Error {}

extension Data {
    func withJuiceboxUnmanagedDataArray<Result>(
        _ body: (JuiceboxUnmanagedDataArray) throws -> Result
    ) rethrows -> Result {
        try withUnsafeBytes { bytes in
            try body(.init(
                data: bytes.bindMemory(to: UInt8.self).baseAddress,
                length: bytes.count
            ))
        }
    }

    init?(_ buffer: JuiceboxUnmanagedDataArray) {
        guard let data = buffer.data else { return nil }
        self.init(bytes: data, count: buffer.length)
    }

    public init?(hexString: String) {
        guard hexString.count.isMultiple(of: 2) else {
            return nil
        }

        let characters = hexString.map { $0 }
        let bytes = stride(from: 0, to: characters.count, by: 2)
            .map { String(characters[$0]) + String(characters[$0 + 1]) }
            .compactMap { UInt8($0, radix: 16) }

        guard hexString.count / bytes.count == 2 else { return nil }

        self.init(bytes)
    }
}

extension URLRequest {
    init(juicebox: JuiceboxHttpRequest) {
        self.init(url: URL(string: String(cString: juicebox.url))!)
        switch juicebox.method {
        case JuiceboxHttpRequestMethodGet:
            self.httpMethod = "GET"
        case JuiceboxHttpRequestMethodPut:
            self.httpMethod = "PUT"
        case JuiceboxHttpRequestMethodDelete:
            self.httpMethod = "DELETE"
        case JuiceboxHttpRequestMethodPost:
            self.httpMethod = "POST"
        default:
            break
        }

        setValue(
            "JuiceboxSdk-Swift/\(String(cString: juicebox_sdk_version()))",
            forHTTPHeaderField: "User-Agent"
        )

        setValue(
            String(cString: juicebox_sdk_version()),
            forHTTPHeaderField: "Juicebox-Version"
        )

        if let headers = juicebox.headers.data {
            Array(UnsafeBufferPointer(start: headers, count: juicebox.headers.length)).map {
                (String(cString: $0.name), String(cString: $0.value))
            }.forEach { name, value in
                setValue(value, forHTTPHeaderField: name)
            }
        }

        httpBody = .init(juicebox.body)
    }
}
