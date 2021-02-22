use std::{
    collections::{BTreeMap, HashMap},
};
use log::debug;
use num_bigint::Sign;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::EcKey,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    sha::sha256,
    sign::Signer,
};
use serde_json::{Value, to_string, to_value};
use simple_asn1::{ASN1Block, from_der};
use crate::error::{Error, Result};
use crate::helper::b64;

#[derive(Clone, Debug)]
pub enum KeyAlg {
    /// An ED25519 keypair; algorithm (P-256/P-384/P-512) is determined by curve used.
    Ed25519(EcKey<Private>),

    /// An RSA keypair using RSASSA-PKCS1-v1_5 using SHA-256
    RsaSha256(Rsa<Private>),
}

impl KeyAlg {
    /// Returns the JWS header for the public portion of the key.
    /// 
    /// If `key_id` is specified, it is inserted into the header instead of the specific values for the key. The JWS
    /// algorithm (`alg`), `url`, and `nonce` values are still inserted.
    /// 
    /// Format of Elliptic Curve keys
    /// ```json
    /// {
    ///     "alg": "P-256",  (or "P-384"/"P-521")
    ///     "url": "<url>",
    ///     "nonce": "<nonce-value>",
    ///     "kty": "EC",
    ///     "crv": "P-256",
    ///     "x": "<x-coordinate in base64url, big-endian>",
    ///     "y": "<y-coordinate in base64url, big-endian>"
    /// }
    /// ```
    /// 
    /// /// Format of RSA keys, from [RFC 7517 §A.1](https://tools.ietf.org/html/rfc7517#appendix-A.1):
    /// ```json
    /// {
    ///     "alg": "RS256",
    ///     "url": "<url>",
    ///     "nonce": "<nonce-value>",
    ///     "kty": "RSA",
    ///     "n": "<n/modulus in base64url, big-endian>",
    ///     "e": "<e/exponent in base64url, big-endian>"
    /// }
    /// ```
    pub fn get_header(&self, url: &str, nonce: &str, key_id: Option<&str>) -> Result<Value> {
        match self {
            Self::Ed25519(key) => {
                let group = key.group();
                let (alg, curve_name) = get_ec_alg_crv(group.curve_name())?;
            
                let pubkey = key.public_key();
                let mut x = BigNum::new()?;
                let mut y = BigNum::new()?;
                let mut ctx = BigNumContext::new()?;
                pubkey.affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;
            
                let mut header: HashMap<String, Value> = HashMap::new();
                header.insert("alg".to_string(), to_value(alg)?);
                header.insert("url".to_string(), to_value(url)?);
                header.insert("nonce".to_string(), to_value(nonce)?);

                match key_id {
                    None => {
                        let mut jwk: BTreeMap<String, String> = BTreeMap::new();
                        jwk.insert("kty".to_string(), "EC".to_string());
                        jwk.insert("crv".to_string(), curve_name.to_string());
                        jwk.insert("x".to_string(), b64(&x.to_vec()));
                        jwk.insert("y".to_string(), b64(&y.to_vec()));
                    
                        header.insert("jwk".to_string(), to_value(jwk)?);
                    }
                    Some(v) => {
                        header.insert("kid".to_string(), to_value(v)?);
                    }
                }
    
                Ok(to_value(header)?)
            },
            Self::RsaSha256(key) => {
                let mut header: HashMap<String, Value> = HashMap::new();
                header.insert("alg".to_string(), to_value("RS256")?);
                header.insert("url".to_string(), to_value(url)?);
                header.insert("nonce".to_string(), to_value(nonce)?);

                match key_id {
                    None => {
                        let mut jwk: BTreeMap<String, String> = BTreeMap::new();
                        jwk.insert("kty".to_string(), "RSA".to_string());
                        jwk.insert("e".to_string(), b64(key.e().to_vec()));
                        jwk.insert("n".to_string(), b64(key.n().to_vec()));

                        header.insert("jwk".to_string(), to_value(jwk)?);
                    }
                    Some(v) => {
                        header.insert("kid".to_string(), to_value(v)?);
                    }
                }
                Ok(to_value(header)?)
            },
        }
    }

    /// Signs the protected header and payload, producing a base64url signature.
    pub fn get_signature(&self, protected_header: &str, payload: &str) -> Result<String> {
        let string_to_sign = format!("{}.{}", protected_header, payload);
        match self {
            Self::Ed25519(key) => {
                let pkey = PKey::from_ec_key(key.clone())?;
                let mut signer = Signer::new(get_digest_for_ec_key(&key)?, &pkey)?;
                let signature_der_bytes = signer.sign_oneshot_to_vec(string_to_sign.as_bytes())?;
                let asn1_blocks = from_der(&signature_der_bytes)?;
                let signature_bytes = der_sig_to_bytes(&asn1_blocks)?;
                Ok(b64(signature_bytes))
            }
            Self::RsaSha256(key) => {
                let pkey = PKey::from_rsa(key.clone())?;
                let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
                signer.update(string_to_sign.as_bytes())?;
                let signature_bytes = signer.sign_to_vec()?;
                debug!(target: "acmev02", "Signature bytes length: {}", signature_bytes.len());
                Ok(b64(signature_bytes))
            }
        }
    }

    /// Returns the JWK tumbprint value encoded in base64url for the key.
    /// See [RFC 7638](https://tools.ietf.org/html/rfc7638) for details.
    pub fn get_thumbprint_b64(&self) -> Result<String> {
        let jwk: BTreeMap<&'static str, String> = match self {
            Self::Ed25519(key) => {
                let group = key.group();
                let curve_name = get_ec_alg_crv(group.curve_name())?.1;

                let pubkey = key.public_key();
                let mut x = BigNum::new()?;
                let mut y = BigNum::new()?;
                let mut ctx = BigNumContext::new()?;
                pubkey.affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;

                let mut jwk = BTreeMap::new();
                jwk.insert("crv", curve_name.to_string());
                jwk.insert("kty", "EC".to_string());
                jwk.insert("x", b64(&x.to_vec()));
                jwk.insert("y", b64(&y.to_vec()));
                jwk
            }
            Self::RsaSha256(key) => {
                let mut jwk = BTreeMap::new();
                jwk.insert("kty", "RSA".to_string());
                jwk.insert("e", b64(key.e().to_vec()));
                jwk.insert("n", b64(key.n().to_vec()));
                jwk
            }
        };
        let jwk_str = to_string(&to_value(jwk)?)?;
        debug!("jwk_str: {}", jwk_str);
        let jwk_sha = sha256(&jwk_str.as_bytes());
        Ok(b64(jwk_sha))
    }

    /// Returns an ACMEv02 key authorization in the form: `<token>.<thumbprint_b64>`.
    /// See [RFC 8555 §8.1](https://tools.ietf.org/html/rfc8555#section-8.1).
    pub fn get_key_authorization(&self, token: &str) -> Result<String> {
        Ok(format!("{}.{}", token, self.get_thumbprint_b64()?))
    }
}

fn get_digest_for_ec_key(key: &EcKey<Private>) -> Result<MessageDigest> {
    match key.group().curve_name() {
        None => Err(Error::invalid_ec_key("EC key does not have an associated named curve")),
        Some(nid) => match nid {
            Nid::X9_62_PRIME256V1 => Ok(MessageDigest::sha256()),
            Nid::SECP384R1 => Ok(MessageDigest::sha384()),
            Nid::SECP521R1 => Ok(MessageDigest::sha512()),
            _ => Err(Error::invalid_ec_key("EC key does not have a recognized EC curve")),
        }
    }
}

/// Return the JWK `alg` and `crv` values for a given elliptic curve.
fn get_ec_alg_crv(curve_name: Option<Nid>) -> Result<(&'static str, &'static str)> {
    match curve_name {
        None => return Err(Error::invalid_ec_key("EC key does not have an associated named curve")),
        Some(nid) => match nid {
            Nid::X9_62_PRIME256V1 => Ok(("ES256", "P-256")),
            Nid::SECP384R1 => Ok(("ES384", "P-384")),
            Nid::SECP521R1 => Ok(("ES512", "P-521")),
            _ => return Err(Error::invalid_ec_key("EC key does not have a recognized EC curve")),
        }
    }
}

fn der_sig_to_bytes(der_signature: &[ASN1Block]) -> Result<Vec<u8>> {
    if der_signature.len() == 1 {
        match &der_signature[0] {
            ASN1Block::Sequence(_, blocks) => {
                if blocks.len() == 2 {
                    let b0 = &blocks[0];
                    let b1 = &blocks[1];

                    match (b0, b1) {
                        (ASN1Block::Integer(_, bi0), ASN1Block::Integer(_, bi1)) => {
                            let (r_sign, r) = bi0.to_bytes_be();
                            let (s_sign, mut s) = bi1.to_bytes_be();

                            if (r_sign == Sign::Plus || r_sign == Sign::NoSign) && (s_sign == Sign::Plus || s_sign == Sign::NoSign) &&
                                r.len() == 32 && s.len() == 32
                            {
                                let mut result = r;
                                result.append(&mut s);
                                Ok(result)
                            } else {
                                Err(Error::invalid_asn1_data(format!("Expected integer byte representations to be 32-bytes each intead of {}/{}: {:?} {:?} {:?} {:?}", r.len(), s.len(), r, s, bi0, bi1)))
                            }
                        }
                        _ => {
                            Err(Error::invalid_asn1_data(format!("Expected inner sequence to be two unsigned or positive integers: ({:?}, {:?})", b0, b1)))
                        }
                    }
                } else {
                    Err(Error::invalid_asn1_data(format!("Expected inner sequence to contain 2 items instead of {}: {:?}", blocks.len(), blocks)))
                }
            }
            _ => {
                Err(Error::invalid_asn1_data(format!("Expected ASN1 block to be a sequence: {:?}", &der_signature[0])))
            }
        }
    } else {
        Err(Error::invalid_asn1_data(format!("Expected one ASN1 block instead of {}: {:?}", der_signature.len(), der_signature)))
    }
}

