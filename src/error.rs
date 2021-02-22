use std::{
    error::Error as StdError,
    fmt::{
        self, Display, Formatter,
    },
    result::{Result as StdResult},
};
use openssl;
use reqwest;
use serde_json;
use simple_asn1;

#[derive(Debug)]
pub enum Error {
    Asn1DecodeError(simple_asn1::ASN1DecodeErr),
    OpenSslError(openssl::error::ErrorStack),
    ReqwestError(reqwest::Error),
    SerdeJsonError(serde_json::error::Error),
    ChallengeTypeNotApplicable(String),
    InvalidAcmeServerResponse(String),
    InvalidAsn1Data(String),
    InvalidECKey(String),
    MissingToken(String),
    Unimplemented(String),
}

impl Error {
    pub(crate) fn invalid_asn1_data<T: Into<String>>(msg: T) -> Self {
        Self::InvalidAsn1Data(msg.into())
    }

    pub(crate) fn invalid_acme_server_response<T: Into<String>>(msg: T) -> Self {
        Self::InvalidAcmeServerResponse(msg.into())
    }

    pub(crate) fn challenge_type_not_applicable<T: Into<String>>(msg: T) -> Self {
        Self::ChallengeTypeNotApplicable(msg.into())
    }

    pub(crate) fn invalid_ec_key<T: Into<String>>(msg: T) -> Self {
        Self::InvalidECKey(msg.into())
    }

    pub(crate) fn missing_token<T: Into<String>>(msg: T) -> Self {
        Self::MissingToken(msg.into())
    }

    #[allow(dead_code)]
    pub(crate) fn unimplemented<T: Into<String>>(msg: T) -> Self {
        Self::Unimplemented(msg.into())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Asn1DecodeError(err) => Some(err),
            Self::OpenSslError(err) => Some(err),
            Self::ReqwestError(err) => Some(err),
            Self::SerdeJsonError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<simple_asn1::ASN1DecodeErr> for Error {
    fn from(err: simple_asn1::ASN1DecodeErr) -> Error {
        Error::Asn1DecodeError(err)
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(err: openssl::error::ErrorStack) -> Error {
        Error::OpenSslError(err)
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        Error::ReqwestError(err)
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(err: serde_json::error::Error) -> Error {
        Error::SerdeJsonError(err)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Asn1DecodeError(err) => write!(f, "acmev02::error::Error::Asn1DecodeError({:#})", err),
            Self::OpenSslError(err) => write!(f, "acmev02::error::Error::OpenSslError({:#})", err),
            Self::ReqwestError(err) => write!(f, "acmev02::error::Error::ReqwestError({:#})", err),
            Self::SerdeJsonError(err) => write!(f, "acmev02::error::Error::SerdeJsonError({:#}", err),
            Self::ChallengeTypeNotApplicable(msg) => write!(f, "acmev02::error::Error::ChallengeTypeNotApplicable({:#})", msg),
            Self::InvalidAcmeServerResponse(msg) => write!(f, "acmev02::error::Error::InvalidAcmeServerResponse({:#})", msg),
            Self::InvalidAsn1Data(msg) => write!(f, "acmev02::error::Error::InvalidAsn1Data({:#})", msg),
            Self::InvalidECKey(msg) => write!(f, "acmev02::error::Error::InvalidECKey({:#})", msg),
            Self::MissingToken(msg) => write!(f, "acmev02::error::Error::MissingToken({:#})", msg),
            Self::Unimplemented(msg) => write!(f, "acmev02::error::Error::Unimplemented({:#})", msg),
        }
    }
}

pub type Result<T> = StdResult<T, Error>;