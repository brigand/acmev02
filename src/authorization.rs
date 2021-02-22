use std::collections::HashMap;
use openssl::{
    sha::sha256,
};
use serde::{self, Serialize, Deserialize};
use serde_json::Value;
use crate::{
    directory::{AcmeBoundDirectory},
    error::{Error, Result},
    helper::b64,
    identifier::AcmeIdentifier,
    key::KeyAlg,
    problem::AcmeProblem,
};

pub const CHALLENGE_TYPE_DNS_01: &str = "dns-01";
pub const CHALLENGE_TYPE_HTTP_01: &str = "http-01";
pub const CHALLENGE_TYPE_TLS_ALPN_01: &str = "tls-alpn-01";

/// ACMEv02 authorization information (proving control of an identity).
/// This holds the information described in [RFC 8555 §7.1.4](https://tools.ietf.org/html/rfc8555#section-7.1.4).
#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeAuthorization {
    /// The identifier that the account is authorized to represent.
    pub identifier: AcmeIdentifier,

    /// The status of this authorization. Possible values are `"pending"`, `"valid"`, `"invalid"`, `"deactivated"`,
    /// `"expired"`, and `"revoked"`.
    pub status: String,

    /// The timestamp after which the server will consider this authorization invalid in
    /// [RFC 3339](https://tools.ietf.org/html/rfc3339) format. This field is **required** if the `status` field
    /// is `"valid"`.
    pub expires: Option<String>,

    /// For pending authorizations, the challenges that the client can fulfill in order to prove possession of the
    /// identifier.  For valid authorizations, the challenge that was validated.  For invalid authorizations, the
    /// challenge that was attempted and failed.
    /// 
    /// Each array entry is an object with parameters required to validate the challenge.  A client should attempt to
    /// fulfill one of these challenges, and a server should consider any one of the challenges sufficient to
    /// make the authorization valid.
    pub challenges: Vec<AcmeChallenge>,

    /// This field **must** be present and true for authorizations created as a result of a newOrder request
    /// containing a DNS identifier with a value that was a wildcard domain name.  For other authorizations, it
    /// **must** be absent.
    pub wildcard: Option<bool>,
}

impl AcmeAuthorization {
    /// Returns the challenge with the specified type, or `None` if a challenge of the type is not found.
    pub fn get_challenge_by_type<'a, 'b>(&'a self, challenge_type: &'b str) -> Option<&'a AcmeChallenge> {
        for ref challenge in &self.challenges {
            if challenge.challenge_type == challenge_type {
                return Some(challenge)
            }
        }
        None
    }
}

/// ACMEv02 challenge information.
/// This is an extensible structure, with the basic fields below as described in
/// [RFC 8555 §8](https://tools.ietf.org/html/rfc8555#section-8).
#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeChallenge {
    /// The type of challenge encoded in the object.
    ///
    /// This is named `type` in RFC 8555; it is renamed here to avoid conflict with the Rust `type` keyword.
    #[serde(rename="type")]
    pub challenge_type: String,

    /// The URL to which a response can be posted.
    pub url: String,

    /// The status of this challenge.  Possible values are `"pending"`, `"processing"`, `"valid"`, and `"invalid"`.
    pub status: String,

    /// The time at which the server validated this challenge in [RFC 3339](https://tools.ietf.org/html/rfc3339)
    /// format. This field is **required** if the `status` field is `"valid"`.
    pub validated: Option<String>,

    /// The error that occurred while processing the order, if any.  This field is structured as an HTTP problem
    /// document describe in [RFC 7807](https://tools.ietf.org/html/rfc7807).
    pub error: Option<AcmeProblem>,

    /// A random value that uniquely identifies the challenge.  This field is required when `challenge_type` is
    /// `"http-01"`, `"dns-01"`, and `"tls-alpn-01"`.
    pub token: Option<String>,

    /// Additional fields specified by the challenge.
    #[serde(flatten)]
    pub additional_fields: HashMap<String, Value>,
}

impl AcmeChallenge {
    pub fn is_dns_01(&self) -> bool {
        self.challenge_type == CHALLENGE_TYPE_DNS_01
    }

    pub fn is_http_01(&self) -> bool {
        self.challenge_type == CHALLENGE_TYPE_HTTP_01
    }

    pub fn is_tls_alpn_01(&self) -> bool {
        self.challenge_type == CHALLENGE_TYPE_TLS_ALPN_01
    }

    pub fn get_txt_record(&self, key: &KeyAlg) -> Result<String> {
        if self.is_dns_01() {
            if let Some(ref token) = self.token {
                let key_authorization = key.get_key_authorization(token)?;
                let challenge_value = format!("\"{}\"", b64(sha256(&key_authorization.as_bytes())));
                Ok(challenge_value)
            } else {
                Err(Error::missing_token(format!("ACME server did not send a token for challenge {:#}", self.challenge_type)))
            }
        } else {
            Err(Error::challenge_type_not_applicable(format!("Challenge type {:#} does not use TXT records", self.challenge_type)))
        }
    }

    pub async fn respond(&self, dir: &AcmeBoundDirectory) -> Result<AcmeChallenge> {
        dir.respond_challenge(&self.url).await
    }
}
