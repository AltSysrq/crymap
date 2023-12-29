//-
// Copyright (c) 2020, Jason Lingle
//
// This file is part of Crymap.
//
// Crymap is free software: you can  redistribute it and/or modify it under the
// terms of  the GNU General Public  License as published by  the Free Software
// Foundation, either version  3 of the License, or (at  your option) any later
// version.
//
// Crymap is distributed  in the hope that  it will be useful,  but WITHOUT ANY
// WARRANTY; without  even the implied  warranty of MERCHANTABILITY  or FITNESS
// FOR  A PARTICULAR  PURPOSE.  See the  GNU General  Public  License for  more
// details.
//
// You should have received a copy of the GNU General Public License along with
// Crymap. If not, see <http://www.gnu.org/licenses/>.

//! Response codes from RFC 5321, and extended response codes from RFC 1893.
//!
//! The module is designed to be wildcard-imported, and defines submodules with
//! short names for accessing the enum values in a consistent way.
#![allow(dead_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum PrimaryCode {
    // In the order RFC 5321 defines them
    CommandSyntaxError = 500,
    ParameterSyntaxError = 501,
    CommandNotImplemented = 502,
    BadSequenceOfCommands = 503,
    CommandParemeterNotImplemented = 504,
    SystemStatus = 211,
    HelpMessage = 214,
    ServiceReady = 220,
    ServiceClosing = 221,
    ServiceNotAvailableClosing = 421,
    Ok = 250,
    WillForward = 251,
    CannotVerify = 252,
    UnableToAccommodateParameters = 455,
    MailOrRecipientParametersNotKnown = 555,
    ActionNotTakenTemporary = 450,
    ActionNotTakenPermanent = 550,
    ActionAborted = 451,
    UserNotLocal = 551,
    // Also TooManyRecipients
    InsufficientStorage = 452,
    ExceededStorageAllocation = 552,
    MailboxNameNotAllowed = 553,
    StartMailInput = 354,
    TransactionFailed = 554,
}

pub mod pc {
    pub use super::PrimaryCode::*;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ClassCode {
    Success = 2,
    TempFail = 4,
    PermFail = 5,
}

pub mod cc {
    pub use super::ClassCode::*;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum SubjectCode {
    Undefined = 0,
    OtherAddressStatus = 10,
    BadDestinationMailboxAddress = 11,
    BadDestinationSystemAddress = 12,
    BadDestinationMailboxAddressSyntax = 13,
    DestinationMailboxAddressAmbiguous = 14,
    DestinationAddressValid = 15,
    DestinationMailboxMoved = 16,
    BadSenderMailboxAddressSyntax = 17,
    BadSenderSystemAddress = 18,
    OtherMailboxStatus = 20,
    MailboxDisabled = 21,
    MailboxFull = 22,
    MessageLengthExceedsLimit = 23,
    MailingListExpansionProblem = 24,
    OtherMailSystem = 30,
    MailSystemFull = 31,
    SystemNotAcceptingNetworkMessages = 32,
    SystemNotCapableOfSelectedFeatures = 33,
    MessageTooBigForSystem = 34,
    SystemIncorrectlyConfigured = 35,
    OtherNetwork = 40,
    NoAnswerFromHost = 41,
    BadConnection = 42,
    DirectoryServerFailure = 43,
    UnableToRoute = 44,
    MailSystemCongestion = 45,
    RoutingLoopDetected = 46,
    DeliveryTimeExpired = 47,
    OtherProtocolStatus = 50,
    InvalidCommand = 51,
    SyntaxError = 52,
    TooManyRecipients = 53,
    InvalidCommandArguments = 54,
    WrongProtocolVersion = 55,
    OtherMediaError = 60,
    MediaNotSupported = 61,
    ConversionRequiredAndProhibited = 62,
    ConversionRequiredButNotSupported = 63,
    ConversionWithLossPerformed = 64,
    ConversionFailed = 65,
    OtherSecurity = 70,
    DeliveryNotAuthorised = 71,
    MailingListExpansionProhibited = 72,
    SecurityConversionRequiredButNotPossible = 73,
    SecurityFeaturesNotSupported = 74,
    CryptographicFailure = 75,
    CryptographicAlgorithmNotSupported = 76,
    MessageIntegrityFailure = 77,
}

pub mod sc {
    pub use super::SubjectCode::*;
}
