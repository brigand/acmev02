use serde::{self, Serialize, Deserialize};

/// ACMEv02 identifier objects.
/// This is used in various places in [RFC 8555](https tools.ietf.org/html/rfc8555) but does not have a singular
/// referencable definition in the RFC.
/// 
/// Currently, only DNS identifiers have been defined by the RFC.
#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeIdentifier {
    /// The type of identifier.  RFC 8555 defines the `"dns"` identifier type and is currently the only type supported.
    /// 
    /// This is named `type` in RFC 8555; it is renamed here to avoid conflict with the Rust `type` keyword.
    #[serde(rename="type")]
    pub identifier_type: String,

    /// The identifier itself.
    pub value: String,
}

impl AcmeIdentifier {
    pub fn new<S1: Into<String>, S2: Into<String>>(identifier_type: S1, value: S2) -> Self {
        Self { identifier_type: identifier_type.into(), value: value.into() }
    }

    pub fn dns<S: Into<String>>(value: S) -> Self {
        Self::new("dns", value)
    }
}

