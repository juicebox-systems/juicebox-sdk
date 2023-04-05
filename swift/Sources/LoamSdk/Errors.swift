//
//  Errors.swift
//  
//
//  Created by Nora Trapp on 4/3/23.
//

import Foundation
import LoamSdkFfi

public enum DeleteError: Error {
    case invalidAuth
    case networkError
    case protocolError

    init(_ error: LoamDeleteError) {
        switch error {
        case LoamDeleteErrorInvalidAuth: self = .invalidAuth
        case LoamDeleteErrorNetworkError: self = .networkError
        case LoamDeleteErrorProtocolError: self = .protocolError
        default: fatalError("Unexpected error type \(error)")
        }
    }
}

public enum RecoverError: Error {
    case invalidAuth
    case networkError
    case unsuccessful
    case protocolError

    init(_ error: LoamRecoverError) {
        switch error {
        case LoamRecoverErrorInvalidAuth: self = .invalidAuth
        case LoamRecoverErrorNetworkError: self = .networkError
        case LoamRecoverErrorUnsuccessful: self = .unsuccessful
        case LoamRecoverErrorProtocolError: self = .protocolError
        default: fatalError("Unexpected error type \(error)")
        }
    }
}

public enum RegisterError: Error {
    case invalidAuth
    case networkError
    case protocolError
    case unavailable

    init(_ error: LoamRegisterError) {
        switch error {
        case LoamRegisterErrorInvalidAuth: self = .invalidAuth
        case LoamRegisterErrorNetworkError: self = .networkError
        case LoamRegisterErrorUnavailable: self = .unavailable
        case LoamRegisterErrorProtocolError: self = .protocolError
        default: fatalError("Unexpected error type \(error)")
        }
    }
}
