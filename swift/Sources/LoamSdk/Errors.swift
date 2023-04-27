//
//  Errors.swift
//
//
//  Created by Nora Trapp on 4/3/23.
//

import Foundation
import LoamSdkFfi

/// Error thrown from `Client.deleteAll`
public enum DeleteError: Error {
    /// A transient error in sending or receiving requests to a realm.
    case invalidAuth
    /// A software error has occured. This request should not be retried
    /// with the same parameters. Verify your inputs, check for software,
    /// updates and try again.
    case assertion
    /// A transient error in sending or receiving requests to a realm.
    /// This request may succeed by trying again with the same parameters.
    case transient

    init(_ error: LoamDeleteError) {
        switch error {
        case LoamDeleteErrorInvalidAuth: self = .invalidAuth
        case LoamDeleteErrorTransient: self = .transient
        case LoamDeleteErrorAssertion: self = .assertion
        default: fatalError("Unexpected error type \(error)")
        }
    }
}

/// Error thrown from `Client.recover`
public enum RecoverError: Error {
    /// The secret could not be unlocked, but you can try again
    /// with a different PIN if you have guesses remaining. If no
    /// guesses remain, this secret is locked and unaccessible.
    case invalidPin(guessesRemaining: UInt16)
    /// The secret was not registered or not fully registered with the
    /// provided realms.
    case notRegistered
    /// A realm rejected the `Client`'s auth token.
    case invalidAuth
    /// A software error has occured. This request should not be retried
    /// with the same parameters. Verify your inputs, check for software,
    /// updates and try again.
    case assertion
    /// A transient error in sending or receiving requests to a realm.
    /// This request may succeed by trying again with the same parameters.
    case transient

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

/// Error thrown from `Client.register`
public enum RegisterError: Error {
    /// A realm rejected the `Client`'s auth token.
    case invalidAuth
    /// A software error has occured. This request should not be retried
    /// with the same parameters. Verify your inputs, check for software,
    /// updates and try again.
    case assertion
    /// A transient error in sending or receiving requests to a realm.
    /// This request may succeed by trying again with the same parameters.
    case transient

    init(_ error: LoamRegisterError) {
        switch error {
        case LoamRegisterErrorInvalidAuth: self = .invalidAuth
        case LoamRegisterErrorTransient: self = .transient
        case LoamRegisterErrorAssertion: self = .assertion
        default: fatalError("Unexpected error type \(error)")
        }
    }
}
