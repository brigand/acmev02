use serde::{self, Serialize, Deserialize};
use crate::{
    authorization::AcmeAuthorization,
    directory::AcmeBoundDirectory,
    error::Result,
    identifier::AcmeIdentifier,
    problem::AcmeProblem,
};

/// ACMEv02 order information (request for a certificate).
/// This holds the information described in [RFC 8555 §7.1.3](https tools.ietf.org/html/rfc8555#section-7.1.3).
#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeOrder {
    ///  The status of this order.  Possible values are `"pending"`, `"ready"`, `"processing"`, `"valid"`, and
    /// `"invalid"`.
    pub status: String,

    /// The timestamp after which the server will consider this order invalid, in
    /// [RFC 3339](https://tools.ietf.org/html/rfc3339) format.  This field is REQUIRED for objects with `"pending"`
    /// or `"valid"` in the status field.
    pub expires: Option<String>,

    /// An array of identifier objects that the order pertains to.
    pub identifiers: Vec<AcmeIdentifier>,

    /// The requested value of the `notBefore` field in the certificate in
    /// [RFC 3339](https://tools.ietf.org/html/rfc3339) format.
    #[serde(rename="notBefore")]
    pub not_before: Option<String>,

    /// The requested value of the `notAfter` field in the certificate in
    /// [RFC 3339](https://tools.ietf.org/html/rfc3339) format.
    #[serde(rename="notBefore")]
    pub not_after: Option<String>,

    /// The error that occurred while processing the order, if any.  This field is structured as an HTTP problem
    /// document describe in [RFC 7807](https://tools.ietf.org/html/rfc7807).
    pub error: Option<AcmeProblem>,

    /// For pending orders, the authorizations that the client needs to complete before th requested certificate can
    /// be issued (as described in [RFC 8555 §7.5](https://tools.ietf.org/html/rfc8555#section-7.5)), including
    /// unexpired authorizations that the client has completed in the past for identifiers specified in the order.
    /// The authorizations required are dictated by server policy; there may not be a 1:1 relationship between the
    /// order identifiers and the authorizations required.
    /// 
    /// For final orders (in the `"valid"` or `"invalid"` state), the authorizations that were completed.  Each entry
    /// is a URL from which an authorization can be fetched with a POST-as-GET request.
    pub authorizations: Vec<String>,

    /// A URL that a CSR must be POSTed to once all of the order's authorizations are satisfied to finalize the
    /// order.  The result of a successful finalization will be the population of the certificate URL for the order.
    pub finalize: String,

    /// A URL for the certificate that has been issued in response to this order.
    pub certificate: Option<String>,
}

impl AcmeOrder {
    pub async fn get_authorizations(&self, dir: &AcmeBoundDirectory) -> Result<Vec<(String, AcmeAuthorization)>> {
        let mut futures = Vec::with_capacity(self.authorizations.len());

        for auth_url in &self.authorizations {
            futures.push((auth_url, dir.get_authorization(&auth_url)));
        }

        let mut result = Vec::with_capacity(self.authorizations.len());
        for future in futures {
            result.push((future.0.to_string(), future.1.await?));
        }

        Ok(result)
    }
}

/// ACMEv02 order request.
/// This holds the information described in [RFC 8555 §7.4](https://tools.ietf.org/html/rfc8555#section-7.4).
#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeOrderRequest {
    /// An array of identifiers the client is requesting certificates for.
    pub identifiers: Vec<AcmeIdentifier>,

    /// The requested value of the `notBefore` field in the certificate in
    /// [RFC 3339](https://tools.ietf.org/html/rfc3339) format.
    #[serde(rename="notBefore")]
    pub not_before: Option<String>,

    /// The requested value of the `notAfter` field in the certificate in
    /// [RFC 3339](https://tools.ietf.org/html/rfc3339) format.
    #[serde(rename="notBefore")]
    pub not_after: Option<String>,
}

impl AcmeOrderRequest {
    pub fn new<I, S1, S2>(identifiers: I, not_before: S1, not_after: S2) -> Self
    where
        I: Into<Vec<AcmeIdentifier>>,
        S1: Into<String>,
        S2: Into<String>
    {
        Self { identifiers: identifiers.into(), not_before: Some(not_before.into()), not_after: Some(not_after.into()) }
    }

    pub fn for_identifiers<I>(identifiers: I) -> Self
    where
        I: Into<Vec<AcmeIdentifier>>
    {
        Self { identifiers: identifiers.into(), not_before: None, not_after: None }
    }
}

/// ACMEv02 order finalization.
/// This holds the CSR of the signing request and is sent after the authorizations have concluded.
#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeOrderFinalization {
    /// A CSR encoding the parameters for the certificate being requested
    /// ([RFC 2986](https://tools.ietf.org/html/rfc2986)).
    pub csr: String,
}