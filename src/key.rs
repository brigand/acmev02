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
    sign::Signer,
};
use serde_json::{Value, to_value};
use simple_asn1::{ASN1Block, from_der};
use crate::error::{Error, Result};
use crate::helper::b64;

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

pub enum KeyAlg {
    /// An ED25519 keypair; algorithm (P-256/P-384/P-512) is determined by curve used.
    Ed25519(EcKey<Private>),

    /// An RSA keypair using RSASSA-PKCS1-v1_5 using SHA-256
    RsaSha256(Rsa<Private>),
}

impl KeyAlg {
    /// Format of Elliptic Curve keys, from [RFC 7517 §A.1](https://tools.ietf.org/html/rfc7517#appendix-A.1):
    /// ```json
    /// {
    ///     "kty": "EC",
    ///     "crv": "P-256",
    ///     "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    ///     "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
    /// }
    /// ```
    /// 
    /// /// Format of RSA keys, from [RFC 7517 §A.1](https://tools.ietf.org/html/rfc7517#appendix-A.1):
    /// ```json
    /// {
    ///     "kty": "RSA",
    ///     "n": "0vx7agoebGc...FTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    ///     "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    ///     "e": "AQAB"
    /// }
    /// ```
    pub fn get_header(&self, url: &str, nonce: &str) -> Result<Value> {
        match self {
            Self::Ed25519(key) => {
                let group = key.group();
                let (alg, curve_name) = match group.curve_name() {
                    None => return Err(Error::new_invalid_ec_key("EC key does not have an associated named curve")),
                    Some(nid) => match nid {
                        Nid::X9_62_PRIME256V1 => ("ES256", "P-256"),
                        Nid::SECP384R1 => ("ES384", "P-384"),
                        Nid::SECP521R1 => ("ES512", "P-521"),
                        _ => return Err(Error::new_invalid_ec_key("EC key does not have a recognized EC curve")),
                    }
                };
            
                let pubkey = key.public_key();
                let mut x = BigNum::new()?;
                let mut y = BigNum::new()?;
                let mut ctx = BigNumContext::new()?;
                pubkey.affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;
            
                let mut jwk: BTreeMap<String, String> = BTreeMap::new();
                jwk.insert("kty".to_owned(), "EC".to_owned());
                jwk.insert("crv".to_owned(), curve_name.to_owned());
                jwk.insert("x".to_owned(), b64(&x.to_vec()));
                jwk.insert("y".to_owned(), b64(&y.to_vec()));
            
                let mut header: HashMap<String, Value> = HashMap::new();
                header.insert("alg".to_owned(), to_value(alg)?);
                header.insert("url".to_owned(), to_value(url)?);
                header.insert("nonce".to_owned(), to_value(nonce)?);
                header.insert("jwk".to_owned(), to_value(jwk)?);
                Ok(to_value(header)?)
            },
            Self::RsaSha256(key) => {
                let mut jwk: BTreeMap<String, String> = BTreeMap::new();
                jwk.insert("kty".to_owned(), "RSA".to_owned());
                jwk.insert("e".to_owned(), b64(key.e().to_vec()));
                jwk.insert("n".to_owned(), b64(key.n().to_vec()));

                let mut header: HashMap<String, Value> = HashMap::new();
                header.insert("alg".to_owned(), to_value("RS256")?);
                header.insert("url".to_owned(), to_value(url)?);
                header.insert("nonce".to_owned(), to_value(nonce)?);
                header.insert("jwk".to_owned(), to_value(jwk)?);
                Ok(to_value(header)?)
            },
        }
    }

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
}

fn get_digest_for_ec_key(key: &EcKey<Private>) -> Result<MessageDigest> {
    match key.group().curve_name() {
        None => Err(Error::new_invalid_ec_key("EC key does not have an associated named curve")),
        Some(nid) => match nid {
            Nid::X9_62_PRIME256V1 => Ok(MessageDigest::sha256()),
            Nid::SECP384R1 => Ok(MessageDigest::sha384()),
            Nid::SECP521R1 => Ok(MessageDigest::sha512()),
            _ => Err(Error::new_invalid_ec_key("EC key does not have a recognized EC curve")),
        }
    }
}