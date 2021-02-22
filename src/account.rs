use std::{
    collections::HashMap,
};
use serde::{self, Serialize, Deserialize};
use serde_json::Value;

/// ACMEv02 account information.
/// This holds the information described in [RFC 8555 §7.1.2](https://tools.ietf.org/html/rfc8555#section-7.1.2).
#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeAccount {
    /// The status of this account.  Possible values are `"valid"`, `"deactivated"`, and `"revoked"`.  The value
    /// `"deactivated"` should be used to indicate client-initiated deactivation whereas `"revoked"` should be used to
    /// indicate server-initiated deactivation.
    pub status: String,

    /// An optional array of URLs that the server can use to contact the client for issues related to this account.
    /// Let's Encrypt only supports `mailto:` URLs at this time.
    pub contact: Option<Vec<String>>,

    /// Including this field in a `newAccount` request with a value of `true` indicates the client's agreement with the
    /// terms of service.  This field cannot be updated by the client.
    #[serde(rename="termsOfServiceAgreed")]
    pub terms_of_service_agreed: Option<bool>,

    /// Including this field in a `newAccount` request indicates approval by the holder of an existing non-ACME account
    /// to bind that account to this ACME account.  This field cannot be updated by the client.
    /// 
    /// This is not used by Let's Encrypt.
    #[serde(rename="externalAccountBinding")]
    pub external_account_binding: Option<Value>,

    /// A URL from which a list of orders submitted by this account can be fetched via a POST-as-GET request, as
    /// described in [RFC 8555 §7.1.2.1](https://tools.ietf.org/html/rfc8555#section-7.1.2.1).
    /// 
    /// This is required, but not implemented by Let's Encrypt
    /// ([Issue 3335](https://github.com/letsencrypt/boulder/issues/3335)).
    pub orders: Option<String>,

    /// Additional fields present that are not definied by RFC 8555.
    #[serde(flatten)]
    pub additional_fields: HashMap<String, Value>,
}

/// ACMEv02 account creation/lookup request.
/// This is the input structure to the newAccount request described in
/// [RFC 8555 §7.3](https://tools.ietf.org/html/rfc8555#section-7.1.2).
#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeAccountRequest {
    /// An optional array of URLs that the server can use to contact the client for issues related to this account.
    /// Let's Encrypt only supports `mailto:` URLs at this time.
    pub contact: Option<Vec<String>>,

    /// Including this field in a `newAccount` request with a value of `true` indicates the client's agreement with the
    /// terms of service.
    #[serde(rename="termsOfServiceAgreed")]
    pub terms_of_service_agreed: Option<bool>,

    /// If this field is present with the value `true`, the server does not create a new account if one does not
    /// already exist.  This allows a client to look up an account URL based on an account key.
    #[serde(rename="onlyReturnExisting")]
    pub only_return_existing: Option<bool>,

    /// Including this field in a `newAccount` request indicates approval by the holder of an existing non-ACME account
    /// to bind that account to this ACME account.  This field cannot be updated by the client.
    /// 
    /// This is not used by Let's Encrypt.
    #[serde(rename="externalAccountBinding")]
    pub external_account_binding: Option<Value>,
}