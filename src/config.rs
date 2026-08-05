use crate::prelude::*;

use std::io::{Read as _, Write as _};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Config {
    pub email: Option<String>,
    pub sso_id: Option<String>,
    pub base_url: Option<String>,
    pub identity_url: Option<String>,
    pub ui_url: Option<String>,
    pub notifications_url: Option<String>,
    #[serde(default = "default_lock_timeout")]
    pub lock_timeout: u64,
    #[serde(default = "default_l1_timeout")]
    pub l1_timeout: u64,
    #[serde(default = "default_sync_interval")]
    pub sync_interval: u64,
    #[serde(default = "default_pinentry")]
    pub pinentry: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unlock_helper: Option<String>,
    pub client_cert_path: Option<std::path::PathBuf>,
    #[serde(default)]
    pub ssh_agent: SshAgentConfig,
    // backcompat, no longer generated in new configs
    #[serde(skip_serializing)]
    pub device_id: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            email: None,
            sso_id: None,
            base_url: None,
            identity_url: None,
            ui_url: None,
            notifications_url: None,
            lock_timeout: default_lock_timeout(),
            l1_timeout: default_l1_timeout(),
            sync_interval: default_sync_interval(),
            pinentry: default_pinentry(),
            unlock_helper: None,
            client_cert_path: None,
            ssh_agent: SshAgentConfig::default(),
            device_id: None,
        }
    }
}

pub fn default_lock_timeout() -> u64 {
    3600
}

pub fn default_l1_timeout() -> u64 {
    24 * 60 * 60
}

pub fn default_sync_interval() -> u64 {
    3600
}

pub fn default_pinentry() -> String {
    "pinentry".to_string()
}

fn normalize_timeouts(config: &mut Config) {
    if config.lock_timeout == 0 {
        log::warn!("lock_timeout must be greater than 0");
        config.lock_timeout = default_lock_timeout();
    }
    if config.l1_timeout == 0 {
        log::warn!("l1_timeout must be greater than 0");
        config.l1_timeout = default_l1_timeout();
    }
}

#[derive(
    serde::Serialize,
    serde::Deserialize,
    Debug,
    Clone,
    Copy,
    Default,
    Eq,
    PartialEq,
)]
#[serde(rename_all = "lowercase")]
pub enum SshAgentPolicy {
    Always,
    #[default]
    L1,
    Never,
}

impl std::str::FromStr for SshAgentPolicy {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "always" => Ok(Self::Always),
            "l1" => Ok(Self::L1),
            "never" => Ok(Self::Never),
            _ => Err(anyhow::anyhow!(
                "invalid SSH agent policy {value:?}; expected always, l1, or never"
            )),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default)]
pub struct SshAgentConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub default_policy: SshAgentPolicy,
    /// Optional policy overrides indexed by an OpenSSH SHA256 fingerprint.
    #[serde(default)]
    pub policies: std::collections::BTreeMap<String, SshAgentPolicy>,
}

impl SshAgentConfig {
    pub fn policy_for(&self, fingerprint: &str) -> SshAgentPolicy {
        self.policies
            .get(fingerprint)
            .copied()
            .unwrap_or(self.default_policy)
    }
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load() -> Result<Self> {
        let file = crate::dirs::config_file();
        let mut fh = std::fs::File::open(&file).map_err(|source| {
            Error::LoadConfig {
                source,
                file: file.clone(),
            }
        })?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .map_err(|source| Error::LoadConfig {
                source,
                file: file.clone(),
            })?;
        let mut slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadConfigJson { source, file })?;
        normalize_timeouts(&mut slf);
        Ok(slf)
    }

    pub async fn load_async() -> Result<Self> {
        let file = crate::dirs::config_file();
        let mut fh =
            tokio::fs::File::open(&file).await.map_err(|source| {
                Error::LoadConfigAsync {
                    source,
                    file: file.clone(),
                }
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json).await.map_err(|source| {
            Error::LoadConfigAsync {
                source,
                file: file.clone(),
            }
        })?;
        let mut slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadConfigJson { source, file })?;
        normalize_timeouts(&mut slf);
        Ok(slf)
    }

    pub fn save(&self) -> Result<()> {
        let file = crate::dirs::config_file();
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        std::fs::create_dir_all(file.parent().unwrap()).map_err(
            |source| Error::SaveConfig {
                source,
                file: file.clone(),
            },
        )?;
        let mut fh = std::fs::File::create(&file).map_err(|source| {
            Error::SaveConfig {
                source,
                file: file.clone(),
            }
        })?;
        fh.write_all(
            serde_json::to_string(self)
                .map_err(|source| Error::SaveConfigJson {
                    source,
                    file: file.clone(),
                })?
                .as_bytes(),
        )
        .map_err(|source| Error::SaveConfig { source, file })?;
        Ok(())
    }

    pub fn validate() -> Result<()> {
        let config = Self::load()?;
        if config.email.is_none() {
            return Err(Error::ConfigMissingEmail);
        }
        Ok(())
    }

    pub fn base_url(&self) -> String {
        self.base_url.clone().map_or_else(
            || "https://api.bitwarden.com".to_string(),
            |url| {
                let clean_url = url.trim_end_matches('/');
                if clean_url == "https://api.bitwarden.eu" {
                    "https://api.bitwarden.eu".to_string()
                } else {
                    format!("{clean_url}/api")
                }
            },
        )
    }

    pub fn identity_url(&self) -> String {
        self.identity_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://identity.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://identity.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/identity")
                    }
                },
            )
        })
    }

    pub fn ui_url(&self) -> String {
        self.ui_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://vault.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://vault.bitwarden.eu".to_string()
                    } else {
                        clean_url.to_string()
                    }
                },
            )
        })
    }

    pub fn notifications_url(&self) -> String {
        self.notifications_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://notifications.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://notifications.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/notifications")
                    }
                },
            )
        })
    }

    pub fn client_cert_path(&self) -> Option<&std::path::Path> {
        self.client_cert_path.as_deref()
    }

    pub fn server_name(&self) -> String {
        self.base_url
            .clone()
            .unwrap_or_else(|| "default".to_string())
    }
}

pub async fn device_id(config: &Config) -> Result<String> {
    let file = crate::dirs::device_id_file();
    if let Ok(mut fh) = tokio::fs::File::open(&file).await {
        let mut s = String::new();
        fh.read_to_string(&mut s)
            .await
            .map_err(|e| Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            })?;
        Ok(s.trim().to_string())
    } else {
        let id = config.device_id.as_ref().map_or_else(
            || uuid::Uuid::new_v4().hyphenated().to_string(),
            String::to_string,
        );
        let mut fh = tokio::fs::File::create(&file).await.map_err(|e| {
            Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            }
        })?;
        fh.write_all(id.as_bytes()).await.map_err(|e| {
            Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            }
        })?;
        Ok(id)
    }
}

/// Return the identifier of a device that has already been registered.
/// Unlike `device_id`, this never creates a new identifier, since an
/// auth-request made by an unknown device is invalid.
pub async fn registered_device_id(config: &Config) -> Result<String> {
    let file = crate::dirs::device_id_file();
    match tokio::fs::File::open(&file).await {
        Ok(mut fh) => {
            let mut id = String::new();
            fh.read_to_string(&mut id).await.map_err(|source| {
                Error::LoadDeviceId {
                    source,
                    file: file.clone(),
                }
            })?;
            let id = id.trim();
            if id.is_empty() {
                Err(Error::KnownDeviceRequired)
            } else {
                Ok(id.to_string())
            }
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            config
                .device_id
                .clone()
                .filter(|id| !id.trim().is_empty())
                .ok_or(Error::KnownDeviceRequired)
        }
        Err(source) => Err(Error::LoadDeviceId { source, file }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l1_timeout_defaults_to_twenty_four_hours() {
        assert_eq!(default_l1_timeout(), 24 * 60 * 60);
        assert_eq!(Config::default().l1_timeout, 24 * 60 * 60);
    }

    #[test]
    fn missing_l1_timeout_is_backward_compatible() {
        let mut value = serde_json::to_value(Config::default()).unwrap();
        value.as_object_mut().unwrap().remove("l1_timeout");
        let config: Config = serde_json::from_value(value).unwrap();
        assert_eq!(config.l1_timeout, default_l1_timeout());
    }

    #[test]
    fn zero_timeouts_are_normalized() {
        let mut config = Config {
            lock_timeout: 0,
            l1_timeout: 0,
            ..Config::default()
        };
        normalize_timeouts(&mut config);
        assert_eq!(config.lock_timeout, default_lock_timeout());
        assert_eq!(config.l1_timeout, default_l1_timeout());
    }

    #[test]
    fn ssh_agent_is_opt_in_and_defaults_to_l1() {
        let config: Config = serde_json::from_str("{}").unwrap();
        assert!(!config.ssh_agent.enabled);
        assert_eq!(config.ssh_agent.default_policy, SshAgentPolicy::L1);
    }

    #[test]
    fn fingerprint_policy_overrides_default() {
        let config: Config = serde_json::from_str(
            r#"{
                "ssh_agent": {
                    "enabled": true,
                    "default_policy": "l1",
                    "policies": {"SHA256:test": "always"}
                }
            }"#,
        )
        .unwrap();
        assert!(config.ssh_agent.enabled);
        assert_eq!(
            config.ssh_agent.policy_for("SHA256:test"),
            SshAgentPolicy::Always
        );
        assert_eq!(
            config.ssh_agent.policy_for("SHA256:other"),
            SshAgentPolicy::L1
        );
    }
}
