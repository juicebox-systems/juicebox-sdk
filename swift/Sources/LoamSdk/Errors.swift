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
        case LoamDeleteErrorNetwork: self = .networkError
        case LoamDeleteErrorProtocol: self = .protocolError
        default: fatalError("Unexpected error type \(error)")
        }
    }
}

public enum RecoverError: Error {
    case invalidAuth
    case networkError
    case unsuccessful(guessesRemaining: UInt16?)
    case protocolError

    init(_ error: LoamRecoverError) {
        switch error.reason {
        case LoamRecoverErrorReasonInvalidAuth: self = .invalidAuth
        case LoamRecoverErrorReasonNetwork: self = .networkError
        case LoamRecoverErrorReasonUnsuccessful: self =
                .unsuccessful(guessesRemaining: error.guesses_remaining?.pointee)
        case LoamRecoverErrorReasonProtocol: self = .protocolError
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
        case LoamRegisterErrorNetwork: self = .networkError
        case LoamRegisterErrorUnavailable: self = .unavailable
        case LoamRegisterErrorProtocol: self = .protocolError
        default: fatalError("Unexpected error type \(error)")
        }
    }
}
