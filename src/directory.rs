use std::{
    cell::RefCell,
    collections::{HashMap},
    sync::Mutex,
};

use log::{debug, error};
use reqwest::{
    self, Client, StatusCode,
    header::{HeaderMap},
};
use serde::{
    self, Serialize, Deserialize,
    de::DeserializeOwned,
};
use serde_json::{Value, to_string, to_value};
use crate::account::{AcmeAccount, AcmeAccountRequest};
use crate::error::{Error, Result};
use crate::helper::b64;
use crate::key::KeyAlg;

/// Default Let's Encrypt directory URL to configure client.
pub const LETSENCRYPT_DIRECTORY_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// Staging Let's Encrypt directory URL.
pub const LETSENCRYPT_STAGING_DIRECTORY_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Default Let's Encrypt agreement URL used in account registration.
pub const LETSENCRYPT_AGREEMENT_URL: &str = "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf";

/// ACMEv02 directory metadata information. All fields are Option and additional information may be present.
#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeDirectoryMetadata {
    /// A URL identifying the current terms of service.
    #[serde(rename="termsOfService")]
    pub terms_os_service: Option<String>,

    /// An HTTP or HTTPS URL locating a website providing more information about the ACME server.
    pub website: Option<String>,

    /// The hostnames that the ACME server recognizes as referring to itself for the purposes of CAA record validation.
    #[serde(rename="caaIdentities")]
    pub caa_identities: Option<Vec<String>>,

    /// If this field is present and set to `true`, then the CA requires that all `newAccount` requests include an
    /// `externalAccountBinding` field associating the new account with an external account.
    #[serde(rename="externalAccountRequired")]
    pub external_account_required: Option<bool>,

    /// Additional fields present that are not definied by RFC 8555.
    #[serde(flatten)]
    pub additional_fields: HashMap<String, Value>,
}

/// ACMEv02 directory information.
/// This holds the information described in [RFC 8555 §7.1.1](https://tools.ietf.org/html/rfc8555#section-7.1.1).
#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeDirectoryInfo {
    /// The URL for changing the public key on the account.
    /// See [RFC 8555 §7.3.5](https://tools.ietf.org/html/rfc8555#section-7.3.5) for details.
    #[serde(rename="keyChange")]
    pub key_change: String,

    /// The URL for establishing a new account.
    /// See [RFC 8555 §7.3](https://tools.ietf.org/html/rfc8555#section-7.3) for details.
    #[serde(rename="newAccount")]
    pub new_account: String,

    /// The URL for performing preauthorization (outside-of-ACME authorization) before requesting a new certficiate.
    /// This is Option and not used by Let's Encrypt.
    /// See [RFC 8555 §7.4.1](https://tools.ietf.org/html/rfc8555#section-7.4.1) for details.
    #[serde(rename="newAuthz")]
    pub new_authz: Option<String>,

    /// The URL for requesting a new nonce value (to prevent replay attacks).
    /// See [RFC 8555 §7.2](https://tools.ietf.org/html/rfc8555#section-7.2) for details.
    #[serde(rename="newNonce")]
    pub new_nonce: String,

    /// The URL for initiating a new certificate order.
    /// See [RFC 8555 §7.4](https://tools.ietf.org/html/rfc8555#section-7.4) for details
    #[serde(rename="newOrder")]
    pub new_order: String,

    /// The URL for revoking a certificate.
    /// See [RFC 8555 §7.6](https://tools.ietf.org/html/rfc8555#section-7.6) for details
    #[serde(rename="revokeCert")]
    pub revoke_cert: String,

    /// Option metadata about the directory service.
    /// See [RFC 8555 §7.1.1](https://tools.ietf.org/html/rfc8555#section-7.1.1) for the defined fields.
    #[serde(rename="meta")]
    pub meta: Option<AcmeDirectoryMetadata>,
}

pub struct AcmeDirectory {
    info: AcmeDirectoryInfo,

    /// Last unused nonce from the server.
    next_nonce: Mutex<RefCell<Option<String>>>,

    /// The keypair used to sign requests to ACME.
    key: KeyAlg,
}

#[derive(Debug, Serialize, Deserialize)]
struct Jws {
    protected: String,
    payload: String,
    signature: String,
}

impl AcmeDirectory {
    /// Create a new AcmeDirectory instance by making an HTTP request to the specified ACMEv02 directory URL and
    /// saving the directory information returned there.
    pub async fn from_url(url: &str, key: KeyAlg) -> Result<AcmeDirectory> {
        let client = Client::new();
        let response = client.get(url).send().await?;
        let response = response.error_for_status()?;
        let nonce = get_nonce_from_response(&response);
        let info = response.json::<AcmeDirectoryInfo>().await?;

        // Just in case the directory includes a Replay-Nonce in its response. Let's Encrypt doesn't do this.
        let next_nonce = Mutex::new(RefCell::new(nonce.ok()));

        let dir = Self{info: info, next_nonce: next_nonce, key: key};
        Ok(dir)
    }

    pub async fn new_account(&mut self, request: &AcmeAccountRequest) -> Result<AcmeAccount> {
        let url = self.info.new_account.clone();
        let (_, _, result) = self.request(&url, request).await?;
        Ok(result)
    }

    /// Make a new POST request to a URL, signed with the key.
    /// This returns the Headers, StatusCode and Value from the reply.
    async fn request<T, V>(&mut self, url: &str, payload: T) -> Result<(HeaderMap, StatusCode, V)>
        where
            T: Serialize,
            V: DeserializeOwned,
    {
        let jws = self.create_jws_request_body(url, payload).await?;
        let jws_string = to_string(&jws)?;
        debug!(target: "acmev02", "jws: {:?}", jws_string);
        let client = Client::new();
        let request = client
            .post(url)
            .body(jws_string)
            .header("content-type", "application/jose+json")
            .build()?;
        debug!(target: "acmev02", "request: {:?}", request);
        
        let response = client.execute(request).await?;

        match get_nonce_from_response(&response) {
            Ok(nonce) => {
                // Save this nonce for future use.
                let rc = self.next_nonce.lock().unwrap();
                (*rc).replace(Some(nonce));
            }
            Err(_) => {
                // Ignore this case.
            }
        }

        let status = response.status();
        if status.as_u16() >= 300 {
            let err = response.error_for_status_ref().unwrap_err();
            let text = response.text().await.unwrap_or("<unknown>".to_string());
            error!(target: "acmev02", "Unexpected response from server: {} - {}", status.as_u16(), text);
            return Err(Error::ReqwestError(err));
        }

        let headers = response.headers().clone();
        let value = response.json::<V>().await?;

        Ok((headers, status, value))
    }
    
    //// Create the JWS request body for a given URL and payload.
    async fn create_jws_request_body<T: Serialize>(&mut self, url: &str, payload: T) -> Result<Jws> {
        let nonce = self.get_nonce().await?;
        let header = self.key.get_header(url, &nonce)?;
        let header64 = b64(to_string(&header)?.as_bytes());

        let payload_json = to_value(&payload)?;
        let payload64 = b64(to_string(&payload_json)?.as_bytes());
        
        let signature = self.key.get_signature(&header64, &payload64)?;

        Ok(Jws{protected: header64, payload: payload64, signature: signature})
    }

    /// Returns a new anti-replay nonce value.
    /// 
    /// Each nonce value can be used only once. ACMEv02 attempts to pre-fill nonce values by including them in
    /// HTTP responses in the `Replay-Nonce` header and the AcmeDirectory instance caches this for use. If this cached
    /// value is availble, it is returned (and the cache voided). If the cached value is unavailable, a new nonce value
    /// is retreived from the remote server.
    pub async fn get_nonce(&mut self) -> Result<String> {
        let rc = self.next_nonce.lock().unwrap();
        let next_nonce = (*rc).replace(None);
        match next_nonce {
            Some(nonce) => Ok(nonce),
            None => self.get_nonce_remote().await
        }
    }

    /// Make an HTTP call to the remove ACME server for a new anti-replay nonce value.
    async fn get_nonce_remote(&self) -> Result<String> {
        let client = Client::new();
        let response = client.get(&self.info.new_nonce).send().await?;
        let response = response.error_for_status()?;
        get_nonce_from_response(&response)
    }
}
    
/// Extracts the anti-replay nonce value from the HTTP header in a response.
fn get_nonce_from_response(response: &reqwest::Response) -> Result<String> {
    let replay_nonce_header = response.headers().get("replay-nonce");
    match replay_nonce_header {
        None => Err(Error::new_invalid_acme_server_response("Replay-Nonce header not found")),
        Some(value_bytes) => {
            let value_str = value_bytes.to_str();
            match value_str {
                Ok(nonce) => Ok(nonce.to_string()),
                Err(_) => Err(Error::new_invalid_acme_server_response("Replay-Nonce header contains invalid characeters"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ctor::ctor;
    use env_logger;
    use log::debug;
    use openssl::{
        ec::EcKey,
    };
    use crate::account::{AcmeAccountRequest};
    use crate::key::KeyAlg;
    use crate::directory::{AcmeDirectory, LETSENCRYPT_STAGING_DIRECTORY_URL};

    const EC_KEY: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPSvFMWfG1r1oZjKUJlvK40DERj2P2Ipyx8peCCL8LguoAoGCCqGSM49
AwEHoUQDQgAE6pzdhXYtfbboKyqGwSuU32UxpcQOmgAavjdmX58wpZ0j9MQ3i9YH
ac60quSOvQ7LOE+veCN0qqdsxTA+q+0MxA==
-----END EC PRIVATE KEY-----";

    #[ctor]
    fn init() {
        env_logger::try_init().unwrap_or_else(|e| eprintln!("Failed to initialize env_logger: {:#}", e));
    }

    #[tokio::test]
    async fn test_account_create() {
        let eckey = EcKey::private_key_from_pem(EC_KEY.as_bytes()).unwrap();
        let keyalg = KeyAlg::Ed25519(eckey);
        let mut dir = AcmeDirectory::from_url(LETSENCRYPT_STAGING_DIRECTORY_URL, keyalg).await.unwrap();
        let req = AcmeAccountRequest{
            contact: Some(vec!["mailto:dacut+acmev02-library-test@kanga.org".to_string()]),
            terms_of_service_agreed: Some(true),
            external_account_binding: None,
            only_return_existing: None,
        };

        let account = dir.new_account(&req).await.unwrap();
        debug!("Account: {:#?}", account);
    }
}