use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

pub const VERSION: u32 = {
    const fn unwrap(res: &Result<u32, std::num::ParseIntError>) -> u32 {
        match res {
            Ok(t) => *t,
            Err(_) => panic!("failed to parse cargo version"),
        }
    }

    let major = env!("CARGO_PKG_VERSION_MAJOR");
    let minor = env!("CARGO_PKG_VERSION_MINOR");
    let patch = env!("CARGO_PKG_VERSION_PATCH");

    unwrap(&u32::from_str_radix(major, 10)) * 1_000_000
        + unwrap(&u32::from_str_radix(minor, 10)) * 1_000_000
        + unwrap(&u32::from_str_radix(patch, 10)) * 1_000_000
};

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct AuthRequestInfo {
    pub id: String,
    pub fingerprint: String,
    pub device_type: String,
    pub ip_address: String,
    pub country_name: Option<String>,
    pub creation_date: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Request {
    tty: Option<String>,
    environment: Option<Environment>,
    action: Action,
}

impl Request {
    pub fn new(environment: Environment, action: Action) -> Self {
        Self {
            tty: None,
            environment: Some(environment),
            action,
        }
    }

    pub fn into_parts(self) -> (Action, Environment) {
        (
            self.action,
            self.environment.unwrap_or_else(|| Environment {
                tty: self.tty.map(|tty| SerializableOsString(tty.into())),
                env_vars: vec![],
            }),
        )
    }
}

// Taken from https://github.com/gpg/gnupg/blob/36dbca3e6944d13e75e96eace634e58a7d7e201d/common/session-env.c#L62-L91
pub const ENVIRONMENT_VARIABLES: &[&str] = &[
    // Used to set ttytype
    "TERM",
    // The X display
    "DISPLAY",
    // Xlib Authentication
    "XAUTHORITY",
    // Used by Xlib to select X input modules (e.g. "@im=SCIM")
    "XMODIFIERS",
    // For the Wayland display engine.
    "WAYLAND_DISPLAY",
    // Used by Qt and other non-GTK toolkits to check for X11 or Wayland
    "XDG_SESSION_TYPE",
    // Used by Qt to explicitly request X11 or Wayland; in particular, needed to
    // make Qt use Wayland on GNOME
    "QT_QPA_PLATFORM",
    // Used by GTK to select GTK input modules (e.g. "scim-bridge")
    "GTK_IM_MODULE",
    // Used by GNOME 3 to talk to gcr over dbus
    "DBUS_SESSION_BUS_ADDRESS",
    // Used by Qt to select Qt input modules (e.g. "xim")
    "QT_IM_MODULE",
    // Used for communication with non-standard Pinentries
    "PINENTRY_USER_DATA",
    // Used to pass window information
    "PINENTRY_GEOM_HINT",
];

pub static ENVIRONMENT_VARIABLES_OS: std::sync::LazyLock<
    Vec<std::ffi::OsString>,
> = std::sync::LazyLock::new(|| {
    ENVIRONMENT_VARIABLES
        .iter()
        .map(std::ffi::OsString::from)
        .collect()
});

#[derive(Hash, PartialEq, Eq, Debug, Clone)]
struct SerializableOsString(std::ffi::OsString);

impl serde::Serialize for SerializableOsString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&crate::base64::encode(self.0.as_bytes()))
    }
}

impl<'de> serde::Deserialize<'de> for SerializableOsString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = SerializableOsString;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("base64 encoded os string")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SerializableOsString(std::ffi::OsString::from_vec(
                    crate::base64::decode(s).map_err(|_| {
                        E::invalid_value(serde::de::Unexpected::Str(s), &self)
                    })?,
                )))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct Environment {
    tty: Option<SerializableOsString>,
    env_vars: Vec<(SerializableOsString, SerializableOsString)>,
}

impl Environment {
    pub fn new(
        tty: Option<std::ffi::OsString>,
        env_vars: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    ) -> Self {
        Self {
            tty: tty.map(SerializableOsString),
            env_vars: env_vars
                .into_iter()
                .map(|(k, v)| {
                    (SerializableOsString(k), SerializableOsString(v))
                })
                .collect(),
        }
    }

    pub fn tty(&self) -> Option<&std::ffi::OsStr> {
        self.tty.as_ref().map(|tty| tty.0.as_os_str())
    }

    pub fn env_vars(
        &self,
    ) -> std::collections::HashMap<std::ffi::OsString, std::ffi::OsString>
    {
        self.env_vars
            .iter()
            .map(|(var, val)| (var.0.clone(), val.0.clone()))
            .filter(|(var, _)| (*ENVIRONMENT_VARIABLES_OS).contains(var))
            .collect()
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Action {
    Login,
    Register,
    Unlock,
    UnlockWithUserKey {
        key: UserKeyMaterial,
    },
    UnlockWithDevice,
    ListAuthRequests,
    ApproveAuthRequest {
        id: String,
    },
    RejectAuthRequest {
        id: String,
    },
    CheckLock,
    Lock,
    Sync,
    Decrypt {
        cipherstring: String,
        entry_key: Option<String>,
        org_id: Option<String>,
    },
    Encrypt {
        plaintext: String,
        org_id: Option<String>,
    },
    ClipboardStore {
        text: String,
    },
    Quit,
    Version,
}

pub struct UserKeyMaterial([u8; crate::locked::KEYS_LEN]);

impl UserKeyMaterial {
    pub fn new(bytes: [u8; crate::locked::KEYS_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; crate::locked::KEYS_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for UserKeyMaterial {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter.write_str("UserKeyMaterial([REDACTED])")
    }
}

impl serde::Serialize for UserKeyMaterial {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&crate::base64::encode(&self.0))
    }
}

impl<'de> serde::Deserialize<'de> for UserKeyMaterial {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let decoded = crate::base64::decode(&encoded)
            .map_err(serde::de::Error::custom)?;
        let bytes = decoded.try_into().map_err(|decoded: Vec<u8>| {
            serde::de::Error::invalid_length(
                decoded.len(),
                &"a 64-byte Bitwarden User Key",
            )
        })?;
        Ok(Self(bytes))
    }
}

impl Drop for UserKeyMaterial {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.0.zeroize();
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Response {
    Ack,
    DeviceAuthPending { id: String, fingerprint: String },
    AuthRequests { requests: Vec<AuthRequestInfo> },
    AuthRequestApproval { request: AuthRequestInfo },
    Error { error: String },
    Decrypt { plaintext: String },
    Encrypt { cipherstring: String },
    Version { version: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> AuthRequestInfo {
        AuthRequestInfo {
            id: "request-id".to_string(),
            fingerprint: "one-two-three-four-five".to_string(),
            device_type: "Linux Desktop".to_string(),
            ip_address: "192.0.2.1".to_string(),
            country_name: Some("Test".to_string()),
            creation_date: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn auth_request_ipc_contains_only_safe_metadata() {
        let response = Response::AuthRequests {
            requests: vec![info()],
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("one-two-three-four-five"));
        assert!(!json.contains("accessCode"));
        assert!(!json.contains("privateKey"));
        assert!(!json.contains("userKey"));
        assert!(!json.contains("pam"));
        assert!(!json.contains("localAuth"));
        assert!(!json.contains("authenticated"));
        let decoded: Response = serde_json::from_str(&json).unwrap();
        match decoded {
            Response::AuthRequests { requests } => {
                assert_eq!(requests, vec![info()]);
            }
            _ => panic!("wrong response variant"),
        }
    }

    #[test]
    fn approval_action_cannot_claim_local_authentication() {
        assert_eq!(
            serde_json::to_value(Action::ApproveAuthRequest {
                id: "00000000-0000-0000-0000-000000000000".to_string(),
            })
            .unwrap(),
            serde_json::json!({
                "type": "ApproveAuthRequest",
                "id": "00000000-0000-0000-0000-000000000000",
            }),
        );
    }

    #[test]
    fn raw_user_key_material_is_redacted_and_strictly_sized() {
        let action = Action::UnlockWithUserKey {
            key: UserKeyMaterial::new([0xabu8; crate::locked::KEYS_LEN]),
        };
        let debug = format!("{action:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("abab"));

        let encoded = serde_json::to_value(&action).unwrap();
        let decoded: Action = serde_json::from_value(encoded).unwrap();
        match decoded {
            Action::UnlockWithUserKey { key } => {
                assert_eq!(
                    key.as_bytes(),
                    &[0xabu8; crate::locked::KEYS_LEN]
                );
            }
            _ => panic!("wrong action variant"),
        }
        assert!(serde_json::from_value::<Action>(serde_json::json!({
            "type": "UnlockWithUserKey",
            "key": crate::base64::encode(&[0_u8; 63]),
        }))
        .is_err());
    }

    #[test]
    fn device_unlock_action_has_no_key_material() {
        assert_eq!(
            serde_json::to_value(Action::UnlockWithDevice).unwrap(),
            serde_json::json!({"type": "UnlockWithDevice"}),
        );
    }
}
