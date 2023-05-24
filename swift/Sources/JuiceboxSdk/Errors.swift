//
//  Errors.swift
//
//
//  Created by Nora Trapp on 4/3/23.
//

import Foundation
import JuiceboxSdkFfi

/// Error thrown from `Client.delete`
public enum DeleteError: Error {
    /// A realm rejected the `Client`'s auth token.
    case invalidAuth
    /// A software error has occurred. This request should not be retried
    /// with the same parameters. Verify your inputs, check for software
    /// updates and try again.
    case assertion
    /// A transient error in sending or receiving requests to a realm.
    /// This request may succeed by trying again with the same parameters.
    case transient

    init(_ error: JuiceboxDeleteError) {
        switch error {
        case JuiceboxDeleteErrorInvalidAuth: self = .invalidAuth
        case JuiceboxDeleteErrorAssertion: self = .assertion
        case JuiceboxDeleteErrorTransient: self = .transient
        default: fatalError("Unexpected error type \(error)")
        }
    }
}

/// Error thrown from `Client.recover`
public enum RecoverError: Error {
    /// The secret could not be unlocked, but you can try again
    /// with a different PIN if you have guesses remaining. If no
    /// guesses remain, this secret is locked and inaccessible.
    case invalidPin(guessesRemaining: UInt16)
    /// The secret was not registered or not fully registered with the
    /// provided realms.
    case notRegistered
    /// A realm rejected the `Client`'s auth token.
    case invalidAuth
    /// A software error has occurred. This request should not be retried
    /// with the same parameters. Verify your inputs, check for software
    /// updates and try again.
    case assertion
    /// A transient error in sending or receiving requests to a realm.
    /// This request may succeed by trying again with the same parameters.
    case transient

    init(_ error: JuiceboxRecoverError) {
        switch error.reason {
        case JuiceboxRecoverErrorReasonInvalidPin: self =
                .invalidPin(guessesRemaining: error.guesses_remaining.pointee)
        case JuiceboxRecoverErrorReasonNotRegistered: self = .notRegistered
        case JuiceboxRecoverErrorReasonInvalidAuth: self = .invalidAuth
        case JuiceboxRecoverErrorReasonAssertion: self = .assertion
        case JuiceboxRecoverErrorReasonTransient: self = .transient
        default: fatalError("Unexpected error type \(error)")
        }
    }
}

/// Error thrown from `Client.register`
public enum RegisterError: Error {
    /// A realm rejected the `Client`'s auth token.
    case invalidAuth
    /// A software error has occurred. This request should not be retried
    /// with the same parameters. Verify your inputs, check for software
    /// updates and try again.
    case assertion
    /// A transient error in sending or receiving requests to a realm.
    /// This request may succeed by trying again with the same parameters.
    case transient

    init(_ error: JuiceboxRegisterError) {
        switch error {
        case JuiceboxRegisterErrorInvalidAuth: self = .invalidAuth
        case JuiceboxRegisterErrorAssertion: self = .assertion
        case JuiceboxRegisterErrorTransient: self = .transient
        default: fatalError("Unexpected error type \(error)")
        }
    }
}
