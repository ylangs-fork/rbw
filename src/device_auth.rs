use crate::prelude::*;

use hkdf::Hkdf;
use pkcs8::{
    DecodePublicKey as _, EncodePrivateKey as _, EncodePublicKey as _,
};
use rand::distr::SampleString as _;
use rsa::traits::PublicKeyParts as _;
use sha2::Digest as _;
use zeroize::Zeroizing;

pub const ACCESS_CODE_LEN: usize = 25;
pub const REQUEST_DEADLINE: std::time::Duration =
    std::time::Duration::from_secs(5 * 60);

/// Ephemeral request material.
///
/// The PKCS#8 private key and access code are zeroized on drop. The access
/// code is sent only in the auth-request HTTP body/query and is never written
/// to the database, IPC responses, or logs.
pub struct RequestKeyPair {
    private_key: pkcs8::SecretDocument,
    public_key: Vec<u8>,
    access_code: Zeroizing<String>,
}

impl RequestKeyPair {
    pub fn generate() -> Result<Self> {
        let mut rng = rand_8::rngs::OsRng;
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|source| Error::Rsa { source })?;
        if private_key.n().bits() != 2048 {
            return Err(Error::DeviceAuth {
                message: "generated RSA key was not 2048 bits".to_string(),
            });
        }
        let public_key = rsa::RsaPublicKey::from(&private_key)
            .to_public_key_der()
            .map_err(|source| Error::DeviceAuth {
                message: format!(
                    "failed to encode auth-request public key: {source}"
                ),
            })?
            .as_bytes()
            .to_vec();
        let private_key = private_key
            .to_pkcs8_der()
            .map_err(|source| Error::RsaPkcs8 { source })?;
        let access_code = Zeroizing::new(
            rand::distr::Alphanumeric
                .sample_string(&mut rand::rng(), ACCESS_CODE_LEN),
        );

        Ok(Self {
            private_key,
            public_key,
            access_code,
        })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn public_key_base64(&self) -> String {
        crate::base64::encode(&self.public_key)
    }

    pub fn access_code(&self) -> &str {
        &self.access_code
    }

    pub fn decrypt_user_key(
        &self,
        encrypted_user_key: &str,
    ) -> Result<crate::locked::Keys> {
        let mut private_key = crate::locked::Vec::new();
        private_key.extend(self.private_key.as_bytes().iter().copied());
        let private_key = crate::locked::PrivateKey::new(private_key);
        let user_key =
            crate::cipherstring::CipherString::new(encrypted_user_key)?
                .decrypt_locked_asymmetric_der(&private_key)?;
        if user_key.data().len() != crate::locked::KEYS_LEN {
            return Err(Error::DeviceAuth {
                message: format!(
                    "auth request returned a {} byte user key, expected {}",
                    user_key.data().len(),
                    crate::locked::KEYS_LEN,
                ),
            });
        }
        Ok(crate::locked::Keys::new(user_key))
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ResponseState<'a> {
    Pending,
    Approved(&'a str),
}

pub fn response_state(
    response: &crate::api::AuthRequest,
) -> Result<ResponseState<'_>> {
    match (
        response.request_approved,
        response.response_date.as_deref(),
        response.key.as_deref(),
    ) {
        (Some(false) | None, None, None) => Ok(ResponseState::Pending),
        (Some(true), Some(_), Some(key)) => Ok(ResponseState::Approved(key)),
        (Some(false), Some(_), None) => Err(Error::DeviceAuth {
            message: "auth request was rejected".to_string(),
        }),
        _ => Err(Error::DeviceAuth {
            message: "auth request returned an inconsistent response state"
                .to_string(),
        }),
    }
}

pub fn encrypt_user_key(
    public_key: &str,
    user_key: &crate::locked::Keys,
) -> Result<String> {
    if user_key.as_bytes().len() != crate::locked::KEYS_LEN {
        return Err(Error::DeviceAuth {
            message: "cannot approve with an invalid user key".to_string(),
        });
    }
    let public_key = crate::base64::decode(public_key)
        .map_err(|source| Error::InvalidBase64 { source })?;
    let public_key = rsa::RsaPublicKey::from_public_key_der(&public_key)
        .map_err(|source| Error::DeviceAuth {
            message: format!("invalid auth-request public key: {source}"),
        })?;
    if public_key.n().bits() != 2048 {
        return Err(Error::DeviceAuth {
            message: "auth-request public key is not RSA-2048".to_string(),
        });
    }
    let ciphertext = public_key
        .encrypt(
            &mut rand_8::rngs::OsRng,
            rsa::Oaep::new::<sha1::Sha1>(),
            user_key.as_bytes(),
        )
        .map_err(|source| Error::Rsa { source })?;
    Ok(format!("4.{}", crate::base64::encode(ciphertext)))
}

pub fn fingerprint(email: &str, public_key: &[u8]) -> Result<String> {
    let key_fingerprint = sha2::Sha256::digest(public_key);
    let hkdf = Hkdf::<sha2::Sha256>::from_prk(&key_fingerprint)
        .map_err(|_| Error::HkdfExpand)?;
    let mut user_fingerprint = [0_u8; 32];
    hkdf.expand(email.to_lowercase().as_bytes(), &mut user_fingerprint)
        .map_err(|_| Error::HkdfExpand)?;
    Ok(hash_phrase(user_fingerprint).join("-"))
}

fn hash_phrase(mut hash: [u8; 32]) -> [&'static str; 5] {
    std::array::from_fn(|_| {
        let mut remainder = 0_u32;
        for byte in &mut hash {
            let value = remainder * 256 + u32::from(*byte);
            *byte = u8::try_from(value / 7_776).unwrap_or(0);
            remainder = value % 7_776;
        }
        crate::wordlist::EFF_LONG[usize::try_from(remainder).unwrap_or(0)]
    })
}

#[cfg(test)]
mod tests {
    use pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};

    use super::*;

    #[test]
    fn generated_request_material_has_expected_wire_formats() {
        let keys = RequestKeyPair::generate().unwrap();
        assert_eq!(keys.access_code().len(), ACCESS_CODE_LEN);
        assert!(keys
            .access_code()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric()));
        let public =
            rsa::RsaPublicKey::from_public_key_der(keys.public_key())
                .unwrap();
        assert_eq!(public.n().bits(), 2048);
        rsa::RsaPrivateKey::from_pkcs8_der(keys.private_key.as_bytes())
            .unwrap();
    }

    #[test]
    fn user_key_round_trip_uses_unsigned_shared_key_cipherstring() {
        let request = RequestKeyPair::generate().unwrap();
        let mut material = crate::locked::Vec::new();
        material.extend(0_u8..64);
        let user_key = crate::locked::Keys::new(material);

        let encrypted =
            encrypt_user_key(&request.public_key_base64(), &user_key)
                .unwrap();
        assert!(encrypted.starts_with("4."));
        let decrypted = request.decrypt_user_key(&encrypted).unwrap();
        assert_eq!(decrypted.as_bytes(), user_key.as_bytes());
    }

    #[test]
    fn rejects_malformed_and_wrong_length_user_keys() {
        let request = RequestKeyPair::generate().unwrap();
        assert!(request.decrypt_user_key("2.bad").is_err());

        let public =
            rsa::RsaPublicKey::from_public_key_der(request.public_key())
                .unwrap();
        let encrypted = public
            .encrypt(
                &mut rand_8::rngs::OsRng,
                rsa::Oaep::new::<sha1::Sha1>(),
                &[7_u8; 32],
            )
            .unwrap();
        let encrypted = format!("4.{}", crate::base64::encode(encrypted));
        assert!(request.decrypt_user_key(&encrypted).is_err());
    }

    fn response(
        approved: Option<bool>,
        key: Option<&str>,
        response_date: Option<&str>,
    ) -> crate::api::AuthRequest {
        crate::api::AuthRequest {
            id: "request-id".to_string(),
            public_key: "public-key".to_string(),
            request_device_type: "Linux Desktop".to_string(),
            request_device_identifier: None,
            request_ip_address: "192.0.2.1".to_string(),
            request_country_name: None,
            key: key.map(str::to_string),
            creation_date: "2026-01-01T00:00:00Z".to_string(),
            response_date: response_date.map(str::to_string),
            request_approved: approved,
        }
    }

    #[test]
    fn response_state_fails_closed() {
        assert_eq!(
            response_state(&response(Some(false), None, None)).unwrap(),
            ResponseState::Pending,
        );
        assert_eq!(
            response_state(&response(Some(true), Some("4.key"), Some("now")))
                .unwrap(),
            ResponseState::Approved("4.key"),
        );
        assert!(response_state(&response(Some(true), None, None)).is_err());
        assert!(response_state(&response(Some(true), Some("4.key"), None))
            .is_err());
        assert!(response_state(&response(Some(false), Some("4.key"), None))
            .is_err());
        assert!(response_state(&response(None, None, Some("now"))).is_err());
        assert!(response_state(&response(Some(false), None, Some("now")))
            .is_err());
    }

    #[test]
    fn fingerprint_matches_official_bitwarden_public_key_vector() {
        let public_key = crate::base64::decode(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvyLRDUwXB4BfQ507D4meFPmwn5zwy3IqTPJO4plrrhnclWahXa240BzyFW9gHgYu+Jrgms5xBfRTBMcEsqqNm7+JpB6C1B6yvnik0DpJgWQw1rwvy4SUYidpR/AWbQi47n/hvnmzI/sQxGddVfvWu1iTKOlf5blbKYAXnUE5DZBGnrWfacNXwRRdtP06tFB0LwDgw+91CeLSJ9py6dm1qX5JIxoO8StJOQl65goLCdrTWlox+0Jh4xFUfCkb+s3px+OhSCzJbvG/hlrSRcUz5GnwlCEyF3v5lfUtV96MJD+78d8pmH6CfFAp2wxKRAbGdk+JccJYO6y6oIXd3Fm7twIDAQAB",
        )
        .unwrap();
        assert_eq!(
            fingerprint("test@bitwarden.com", &public_key).unwrap(),
            "childless-unfair-prowler-dropbox-designate"
        );
    }

    #[test]
    fn hash_phrase_matches_bitwarden_vector() {
        let bytes = crate::base64::decode(
            "V5AQSk83YXd6kZqCncC6d9J72R7UZ60Xl1eIoDoWgTc=",
        )
        .unwrap();
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&bytes);
        assert_eq!(
            hash_phrase(hash),
            ["predefine", "hunting", "pastime", "enrich", "unhearing"]
        );
    }
}
