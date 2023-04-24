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
    case transient
    case assertion

    init(_ error: LoamDeleteError) {
        switch error {
        case LoamDeleteErrorInvalidAuth: self = .invalidAuth
        case LoamDeleteErrorTransient: self = .transient
        case LoamDeleteErrorAssertion: self = .assertion
        default: fatalError("Unexpected error type \(error)")
        }
    }
}

public enum RecoverError: Error {
    case invalidAuth
    case invalidPin(guessesRemaining: UInt16)
    case notRegistered
    case transient
    case assertion

    init(_ error: LoamRecoverError) {
        switch error.reason {
        case LoamRecoverErrorReasonInvalidAuth: self = .invalidAuth
        case LoamRecoverErrorReasonInvalidPin: self =
                .invalidPin(guessesRemaining: error.guesses_remaining.pointee)
        case LoamRecoverErrorReasonNotRegistered: self = .notRegistered
        case LoamRecoverErrorReasonTransient: self = .transient
        case LoamRecoverErrorReasonAssertion: self = .assertion
        default: fatalError("Unexpected error type \(error)")
        }
    }
}

public enum RegisterError: Error {
    case invalidAuth
    case transient
    case assertion

    init(_ error: LoamRegisterError) {
        switch error {
        case LoamRegisterErrorInvalidAuth: self = .invalidAuth
        case LoamRegisterErrorTransient: self = .transient
        case LoamRegisterErrorAssertion: self = .assertion
        default: fatalError("Unexpected error type \(error)")
        }
    }
}
