//! Opt-in face onboarding and read-only inspection of rbw's isolated PAM policy.

use std::io::{IsTerminal as _, Write as _};

use anyhow::Context as _;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[path = "enrollment_preview.rs"]
mod enrollment_preview;

pub fn run(apply: bool) -> anyhow::Result<()> {
    if apply {
        anyhow::ensure!(interactive(), "face setup requires an interactive terminal in your local desktop session");
        enable(true).context("face activation failed")
    } else {
        check()
    }
}

pub fn after_login() -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()?;
    if config.face_auth.is_some() || !interactive() {
        return Ok(());
    }
    eprint!("Enable face authorization for rbw? [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        enable(false).context("login succeeded, but face activation failed")
    } else {
        config.face_auth = Some(false);
        config.save()?;
        crate::commands::reload_session_config()?;
        eprintln!("Face authorization is off. You can enable it later with `rbw setup --apply`.");
        Ok(())
    }
}

fn interactive() -> bool {
    !rustix::process::geteuid().is_root()
        && std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal()
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn enable(reconfigure: bool) -> anyhow::Result<()> {
    linux::enable(reconfigure)
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn check() -> anyhow::Result<()> {
    linux::check()
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn enable(_reconfigure: bool) -> anyhow::Result<()> {
    check()
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn check() -> anyhow::Result<()> {
    anyhow::bail!("face setup requires GNU/Linux and native Howdy")
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod linux {
    use std::fs::{self, File, Metadata, OpenOptions};
    use std::io::{Read as _, Seek as _, Write as _};
    use std::os::unix::fs::{
        MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    };
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use anyhow::{bail, ensure, Context as _};

    const POLICY: &str = "/etc/pam.d/rbw-device-auth";
    const PAM_DIR: &str = "/etc/pam.d";
    const MARKER: &str =
        "# Managed by rbw setup; face authentication only.\n";
    // Only this exact historical Python policy is eligible for migration.
    const LEGACY_POLICY: &str = "#%PAM-1.0\nauth required pam_python3.so /usr/lib/security/howdy/pam.py\naccount required pam_permit.so\n";
    const SYSTEM_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
    // Only distro-controlled system locations, never Homebrew, PATH, an
    // environment override, or a user-supplied module name.
    const MODULE_DIRS: &[&str] = &[
        "/usr/lib/security/rbw-howdy",
        "/usr/lib/security",
        "/usr/lib64/security",
        "/usr/lib/x86_64-linux-gnu/security",
        "/usr/lib/aarch64-linux-gnu/security",
        "/usr/lib/arm-linux-gnueabihf/security",
        "/usr/lib/i386-linux-gnu/security",
        "/usr/lib/riscv64-linux-gnu/security",
        "/usr/lib/powerpc64le-linux-gnu/security",
        "/usr/lib/s390x-linux-gnu/security",
        "/lib/security",
        "/lib64/security",
        "/lib/x86_64-linux-gnu/security",
        "/lib/aarch64-linux-gnu/security",
        "/lib/arm-linux-gnueabihf/security",
        "/lib/i386-linux-gnu/security",
        "/lib/riscv64-linux-gnu/security",
        "/lib/powerpc64le-linux-gnu/security",
        "/lib/s390x-linux-gnu/security",
    ];

    pub(super) fn check() -> anyhow::Result<()> {
        let howdy = find_module("pam_howdy.so")
            .context("native Howdy is missing; use `rbw setup --apply` to enable face authorization")?;
        let permit = find_module("pam_permit.so")?;
        trusted_directory(Path::new(PAM_DIR))?;
        ensure!(
            policy_matches(&policy_text(&howdy, &permit))?,
            "{POLICY} is missing; use `rbw setup --apply`"
        );
        println!("Trusted native Howdy module: {}", howdy.display());
        println!("Dedicated face-only policy: {POLICY}; sudo/login policies are unchanged.");
        println!("Read-only check: hardware authentication is NOT VERIFIED.");
        Ok(())
    }

    pub(super) fn enable(reconfigure: bool) -> anyhow::Result<()> {
        ensure!(
            !rustix::process::geteuid().is_root(),
            "run rbw as your ordinary desktop user, never as root"
        );
        let mut config = rbw::config::Config::load()?;
        let previous = config.face_auth;
        let user = login_user()?;
        let environment = rbw::protocol::Environment::new(
            None,
            std::env::vars_os()
                .filter(|(key, _)| {
                    rbw::protocol::ENVIRONMENT_VARIABLES_OS.contains(key)
                })
                .collect(),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        // Inspect any existing policy BEFORE requesting privilege or changing
        // dependencies. A foreign policy is never silently migrated.
        let existing_howdy = optional_module("pam_howdy.so")?;
        let permit = find_module("pam_permit.so")?;
        trusted_directory(Path::new(PAM_DIR))?;
        let original_policy = policy_contents()?;
        let installed_policy = existing_howdy
            .as_ref()
            .zip(original_policy.as_deref())
            .is_some_and(|(howdy, content)| {
                content == policy_text(howdy, &permit)
            });
        ensure!(
            original_policy.is_none()
                || installed_policy
                || original_policy.as_deref() == Some(LEGACY_POLICY),
            "{POLICY} is not a recognized native or exact legacy policy; refusing to overwrite it. Have an administrator inspect it first"
        );
        eprintln!("Face authorization keeps the master password for cold unlock. Howdy is a convenience check, not hardware-backed identity assurance.");
        eprintln!("rbw will request sudo only to deploy its prebuilt face runtime, configure its isolated policy and enroll your face. It never installs packages, builds code, or changes sudo/login PAM policies.");

        // Existing distro Howdy remains administrator-owned. Reuse a complete
        // enrollment without rewriting its configuration or models.
        let configured = if reconfigure
            && existing_howdy.as_ref().is_some_and(|module| {
                module.starts_with("/usr/lib/security/rbw-howdy")
            }) {
            None
        } else {
            existing_howdy
                .as_deref()
                .map(|module| configured_camera(module, &user))
                .transpose()?
                .flatten()
        };
        let bundled_notifications =
            "/usr/lib/security/rbw-howdy/runtime/bin/notify-send";
        let notifications = if fs::symlink_metadata(bundled_notifications)
            .is_err()
            && configured.is_some()
            && !existing_howdy
                .as_ref()
                .is_some_and(|module| module.starts_with(BUNDLE_ROOT))
        {
            "/usr/bin/notify-send"
        } else {
            bundled_notifications
        };
        let installer = if configured.is_some() {
            if notifications.starts_with(BUNDLE_ROOT) {
                installed_bundle(&bundle_manifest()?)?;
            }
            trusted_file(Path::new(notifications))
                .context("the configured face backend has no trusted notification runtime; face authorization remains disabled")?;
            None
        } else {
            ensure!(!installed_policy || existing_howdy.as_ref().is_some_and(|module| module.starts_with("/usr/lib/security/rbw-howdy")),
                "the existing dedicated policy selects incomplete system Howdy; refusing to migrate or overwrite it");
            Some(Installer::stage()?)
        };
        let mut prepared = false;
        let mut changed_policy = None;
        let mut temporary_preference = false;
        let mut preference_written = false;
        // The ordinary-user preview belongs to the whole transaction, not just
        // the privileged recording subprocess.
        let mut preview = None;
        let mut failure_reason = None;
        let outcome = (|| -> anyhow::Result<()> {
        let result = (|| -> anyhow::Result<()> {
            if installer.is_some() {
                // A real page must connect before Howdy's short recording window.
                preview = Some(super::enrollment_preview::start(true)?);
            }
            let camera = if let Some(camera) = configured {
                camera
            } else {
                let installer =
                    installer.as_ref().context("installer not staged")?;
                let preview = preview.as_ref().context("enrollment preview not started")?;
                let output = installer.prepare(&user, preview)?;
                prepared = true;
                preview.verifying();
                let device = std::str::from_utf8(&output.stdout)?.trim();
                ensure!(
                    device.starts_with("/dev/") && !device.contains('\n'),
                    "installer returned an invalid camera path"
                );
                PathBuf::from(device)
            };
            // Enrollment may need root, but the actual PAM camera access must
            // work for the ordinary desktop user. Never broaden device modes.
            use std::os::unix::fs::FileTypeExt as _;
            ensure!(
                fs::metadata(&camera)?.file_type().is_char_device(),
                "configured camera is not a character device"
            );
            OpenOptions::new().read(true).write(true).open(&camera)
                .context("your desktop user cannot access the camera; no permission or group changes were made")?;
            let howdy = find_module("pam_howdy.so")?;
            let policy = policy_text(&howdy, &permit);
            ensure!(
                policy_contents()? == original_policy,
                "{POLICY} changed during enrollment; refusing to overwrite it"
            );
            if original_policy.as_deref() != Some(policy.as_str()) {
                if previous.is_none() {
                    // A crash must not leave an unanswered legacy preference
                    // auto-detecting the policy before verification succeeded.
                    config.face_auth = Some(false);
                    config.save()?;
                    temporary_preference = true;
                }
                let mut changed = false;
                let installation = install_policy(
                    &policy,
                    original_policy.as_deref(),
                    &mut changed,
                );
                if changed {
                    changed_policy = Some(policy);
                }
                installation?;
            }
            runtime.block_on(rbw::pam_gate::notification_preflight(
                &environment,
            ))?;
            eprintln!("Look into the camera now. Verifying real face authentication as your ordinary user...");
            let gate = rbw::pam_gate::PamGate::new()?.with_context(
                environment,
                "rbw face setup",
                "Verify face authorization before enabling it",
            )?;
            let authorization = runtime.block_on(async {
                if let Some(preview) = preview.as_ref() {
                    tokio::select! {
                        biased;
                        _ = preview.wait_cancelled() => Err(anyhow::anyhow!("Face verification was cancelled.")),
                        result = gate.authorize() => result,
                    }
                } else {
                    gate.authorize().await
                }
            });
            if let Err(error) = authorization {
                // PamGate exposes only static, allowlisted diagnostics. Never
                // render installer output, raw PAM messages, or error chains.
                failure_reason = Some(error.to_string());
                return Err(error).context("real face verification failed or was cancelled; face authorization was not enabled");
            }
            ensure!(!preview.as_ref().is_some_and(|preview| preview.cancelled()),
                "face setup was cancelled");

            // Apply only after setup UI and real PAM have succeeded; the live
            // agent retains master-password-unlocked keys across this cutover.
            config.face_auth = Some(true);
            preference_written = true;
            config.save()?;
            crate::commands::reload_session_config()
                .context("could not activate the new agent mode")?;
            ensure!(!preview.as_ref().is_some_and(|preview| preview.cancelled()),
                "face setup was cancelled");
            Ok(())
        })();
        let transaction = if prepared {
            installer
                .as_ref()
                .context("missing prepared installer")?
                .invoke(
                    if result.is_ok() { "commit" } else { "rollback" },
                    &user,
                )
                .map(|_| ())
        } else {
            Ok(())
        };
        let policy_rollback = if result.is_err() {
            changed_policy.map_or(Ok(()), |expected| -> anyhow::Result<()> {
                ensure!(
                    policy_matches(&expected)?,
                    "newly installed policy changed; refusing rollback"
                );
                if let Some(original) = &original_policy {
                    let mut restored = false;
                    install_policy(original, Some(&expected), &mut restored)?;
                } else {
                    privileged("/usr/bin/rm", &["--".as_ref(), POLICY.as_ref()])?;
                }
                Ok(())
            })
        } else {
            Ok(())
        };
        let cleanup = installer.map_or(Ok(()), Installer::cleanup);
        if let Err(error) = result {
            if preference_written || temporary_preference {
                config.face_auth =
                    if previous.is_none() && policy_rollback.is_err() {
                        // Never let a failed cleanup activate legacy auto-detection.
                        Some(false)
                    } else {
                        previous
                    };
                config.save().context("face activation failed and restoring the previous preference failed")?;
                if preference_written {
                    crate::commands::reload_session_config().context(
                        "failed to restore the previous agent mode",
                    )?;
                }
            }
            transaction.context(
                "face activation failed and enrollment rollback failed",
            )?;
            policy_rollback.context(
                "face activation failed and dedicated-policy rollback failed",
            )?;
            cleanup?;
            return Err(error);
        }
        if let Err(error) = transaction.and(cleanup) {
            eprintln!("Face verification and activation succeeded, but installer cleanup failed: {error:#}");
        }
        eprintln!("Face authorization enabled: real PAM verification succeeded. Your current login is preserved; cold unlock still requires the master password.");
        Ok(())
        })();
        if let Some(preview) = preview.as_ref() {
            if outcome.is_ok() {
                preview.finish("complete", "Real face verification and agent activation succeeded. Return to your terminal.");
            } else {
                preview.finish("failed", failure_reason.as_deref().unwrap_or(
                    "Face setup failed; face authorization was not enabled. Check your terminal.",
                ));
            }
            runtime.block_on(preview.wait_final_ack());
        }
        outcome
    }

    fn login_user() -> anyhow::Result<String> {
        trusted_file(Path::new("/usr/bin/id"))?;
        let output = Command::new("/usr/bin/id")
            .arg("-un")
            .env_clear()
            .env("PATH", SYSTEM_PATH)
            .output()
            .context("failed to resolve login user")?;
        ensure!(output.status.success(), "cannot resolve login user");
        let name = std::str::from_utf8(&output.stdout)?.trim();
        ensure!(!name.is_empty() && !name.starts_with('-') && name.bytes().all(|c| c.is_ascii_alphanumeric() || b"_-.".contains(&c)), "unsupported login user name");
        Ok(name.to_owned())
    }

    fn configured_camera(
        module: &Path,
        user: &str,
    ) -> anyhow::Result<Option<PathBuf>> {
        let base = if module.starts_with("/usr/lib/security/rbw-howdy") {
            "/etc/rbw-howdy"
        } else {
            "/etc/howdy"
        };
        let config = Path::new(base).join("config.ini");
        let model =
            Path::new(base).join("models").join(format!("{user}.dat"));
        if !config.exists() || !model.exists() {
            return Ok(None);
        }
        trusted_file(&config)?;
        trusted_file(&model)?;
        let text = fs::read_to_string(&config)?;
        let mut video = false;
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') {
                video = line == "[video]";
            } else if video {
                if let Some((key, value)) = line.split_once('=') {
                    if key.trim() == "device_path"
                        && value.trim().starts_with("/dev/")
                    {
                        return Ok(Some(PathBuf::from(value.trim())));
                    }
                }
            }
        }
        Ok(None)
    }

    const BUNDLE_ROOT: &str = "/usr/lib/security/rbw-howdy";
    const BUNDLE_PLATFORM: &str = "linux-x86_64-ubuntu22.04";
    // Runtime releases have their own ABI/version lifecycle, independent of rbw.
    const BUNDLE_VERSION: &str = "1.17.0";
    const MIN_GLIBC: (u32, u32) = (2, 35);

    #[derive(serde::Deserialize)]
    struct BundleManifest {
        version: String,
        platform: String,
        sha256: String,
    }

    fn bundle_manifest() -> anyhow::Result<BundleManifest> {
        let manifest: BundleManifest =
            serde_json::from_str(include_str!("face-runtime.json"))?;
        ensure!(
            manifest.version == BUNDLE_VERSION
                && manifest.platform == BUNDLE_PLATFORM
                && manifest.sha256.len() == 64
                && manifest
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "this rbw release has no matching prebuilt face runtime"
        );
        Ok(manifest)
    }

    fn file_digest(path: &Path) -> anyhow::Result<String> {
        use sha2::{Digest as _, Sha256};
        let mut file = open_regular(path)?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        Ok(format!("{:x}", digest.finalize()))
    }

    fn trusted_bundle_tree(path: &Path) -> anyhow::Result<usize> {
        let metadata = trusted_metadata(path)?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "face runtime contains a symbolic link"
        );
        if metadata.is_dir() {
            let mut count = 0;
            for entry in fs::read_dir(path)? {
                count += trusted_bundle_tree(&entry?.path())?;
            }
            Ok(count)
        } else {
            ensure!(
                metadata.is_file() && metadata.nlink() == 1,
                "face runtime contains a special or hard-linked file"
            );
            Ok(1)
        }
    }

    fn installed_bundle(manifest: &BundleManifest) -> anyhow::Result<()> {
        let root = Path::new(BUNDLE_ROOT);
        trusted_directory(root)?;
        let installed_files = trusted_bundle_tree(root)?;
        let identity = root.join(".rbw-bundle-sha256");
        trusted_file(&identity)?;
        ensure!(fs::read_to_string(identity)?.trim() == manifest.sha256,
            "existing face runtime differs from this prebuilt release; refusing to overwrite it");
        trusted_file(&root.join(".rbw-managed"))?;
        let inventory_path = root.join("bundle-manifest.json");
        trusted_file(&inventory_path)?;
        let inventory: serde_json::Value =
            serde_json::from_reader(open_regular(&inventory_path)?)?;
        ensure!(inventory["schema"] == 1
            && inventory["version"] == manifest.version
            && inventory["platform"] == manifest.platform,
            "existing face runtime has no matching bundle manifest; refusing to overwrite it");
        let files = inventory["files"]
            .as_object()
            .context("face runtime manifest has no file inventory")?;
        ensure!(!files.is_empty(), "face runtime inventory is empty");
        ensure!(
            installed_files == files.len() + 2,
            "face runtime contains files outside its release inventory"
        );
        for (name, digest) in files {
            let relative = Path::new(name);
            ensure!(
                !relative.as_os_str().is_empty()
                    && relative.components().all(|part| matches!(
                        part,
                        std::path::Component::Normal(_)
                    )),
                "unsafe face runtime inventory path"
            );
            let path = root.join(relative);
            trusted_file(&path)?;
            ensure!(
                file_digest(&path)?
                    == digest
                        .as_str()
                        .context("invalid face runtime file hash")?,
                "installed face runtime file changed: {}",
                path.display()
            );
        }
        for name in [
            "pam_howdy.so",
            "default-config.ini",
            "runtime/bin/python3",
            "runtime/bin/notify-send",
            "runtime/bin/v4l2-ctl",
        ] {
            trusted_file(&root.join(name))?;
        }
        Ok(())
    }

    fn require_bundle_abi() -> anyhow::Result<()> {
        ensure!(cfg!(target_arch = "x86_64"), "prebuilt face runtime is unavailable on this architecture; no source-build fallback is provided");
        // glibc owns this static NUL-terminated string. Query the linked libc
        // directly: distro names, PATH and caller environment are not ABI proof.
        let version = unsafe {
            // SAFETY: glibc returns a permanent, non-null C string.
            std::ffi::CStr::from_ptr(libc::gnu_get_libc_version())
        }
        .to_str()?;
        let mut parts = version.split('.');
        let major: u32 = parts
            .next()
            .context("missing glibc major version")?
            .parse()?;
        let minor: u32 = parts
            .next()
            .context("missing glibc minor version")?
            .parse()?;
        ensure!(
            (major, minor) >= MIN_GLIBC,
            "prebuilt face runtime requires GNU/Linux x86_64 with glibc >= {}.{} (found {version}); no package installation or source-build fallback is provided",
            MIN_GLIBC.0,
            MIN_GLIBC.1
        );
        Ok(())
    }

    fn deploy_bundle() -> anyhow::Result<()> {
        let manifest = bundle_manifest()?;
        require_bundle_abi()?;
        if fs::symlink_metadata(BUNDLE_ROOT).is_ok() {
            return installed_bundle(&manifest);
        }
        let executable = fs::canonicalize(std::env::current_exe()?)?;
        let keg = executable
            .parent()
            .and_then(Path::parent)
            .context("cannot locate the installed rbw keg")?;
        let archive = keg.join("libexec/face-runtime.tar.gz");
        ensure!(fs::symlink_metadata(&archive).is_ok(),
            "the installed rbw package is missing its matching prebuilt face runtime ({}); face authorization remains disabled; no download or source-build fallback is provided",
            archive.display());
        let archive_file = open_regular(&archive)?;
        // Only data crosses from the user-writable keg. Root never executes a
        // helper, interpreter, or library until the root-owned copy is checked.
        trusted_directory(Path::new("/usr/lib"))?;
        let output = privileged(
            "/usr/bin/mktemp",
            &[
                "-d".as_ref(),
                "--".as_ref(),
                "/usr/lib/.rbw-face-deploy.XXXXXXXXXXXX".as_ref(),
            ],
        )?;
        let stage = std::str::from_utf8(&output.stdout)?.trim();
        let suffix = stage
            .strip_prefix("/usr/lib/.rbw-face-deploy.")
            .context("unexpected face deployment staging path")?;
        ensure!(
            suffix.len() == 12
                && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric()),
            "unsafe face deployment staging path"
        );
        let stage = Path::new(stage);
        let result = (|| -> anyhow::Result<()> {
            privileged(
                "/usr/bin/install",
                &[
                    "-d".as_ref(),
                    "-o".as_ref(),
                    "0".as_ref(),
                    "-g".as_ref(),
                    "0".as_ref(),
                    "-m".as_ref(),
                    "0755".as_ref(),
                    "--".as_ref(),
                    stage.as_os_str(),
                ],
            )?;
            trusted_directory(stage)?;
            let snapshot = stage.join("face-runtime.tar.gz");
            privileged_input(
                "/usr/bin/install",
                &[
                    "-o".as_ref(),
                    "0".as_ref(),
                    "-g".as_ref(),
                    "0".as_ref(),
                    "-m".as_ref(),
                    "0644".as_ref(),
                    "--".as_ref(),
                    "/proc/self/fd/0".as_ref(),
                    snapshot.as_os_str(),
                ],
                Some(&archive_file),
            )?;
            trusted_file(&snapshot)?;
            ensure!(fs::symlink_metadata(&snapshot)?.nlink() == 1
                && file_digest(&snapshot)? == manifest.sha256,
                "prebuilt face runtime SHA-256 mismatch; refusing privileged extraction");
            // The checked archive is a release artifact, not arbitrary input.
            // Still reject any member outside the single permitted subtree.
            let listing = privileged(
                "/usr/bin/tar",
                &[
                    "--list".as_ref(),
                    "--gzip".as_ref(),
                    "--file".as_ref(),
                    snapshot.as_os_str(),
                    "--quoting-style=escape".as_ref(),
                ],
            )?;
            let listing = std::str::from_utf8(&listing.stdout)?;
            ensure!(
                !listing.is_empty()
                    && listing.lines().all(|name| {
                        !name.contains('\\')
                            && name.starts_with("rbw-howdy/")
                            && Path::new(name).components().all(|part| {
                                matches!(
                                    part,
                                    std::path::Component::Normal(_)
                                )
                            })
                    }),
                "prebuilt archive contains paths outside rbw-howdy"
            );
            privileged(
                "/usr/bin/tar",
                &[
                    "--extract".as_ref(),
                    "--gzip".as_ref(),
                    "--no-same-owner".as_ref(),
                    "--no-same-permissions".as_ref(),
                    "--file".as_ref(),
                    snapshot.as_os_str(),
                    "--directory".as_ref(),
                    stage.as_os_str(),
                ],
            )?;
            let unpacked = stage.join("rbw-howdy");
            trusted_directory(&unpacked)?;
            trusted_bundle_tree(&unpacked)?;
            // Record the authenticated archive identity as root-owned data.
            let source_dir = tempfile::Builder::new()
                .prefix("rbw-bundle-id-")
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir_in("/tmp")?;
            let mut identity =
                tempfile::NamedTempFile::new_in(source_dir.path())?;
            identity.write_all(manifest.sha256.as_bytes())?;
            identity.flush()?;
            let target = unpacked.join(".rbw-bundle-sha256");
            ensure!(
                fs::symlink_metadata(&target).is_err(),
                "archive contains reserved deployment identity"
            );
            privileged_input(
                "/usr/bin/install",
                &[
                    "-o".as_ref(),
                    "0".as_ref(),
                    "-g".as_ref(),
                    "0".as_ref(),
                    "-m".as_ref(),
                    "0644".as_ref(),
                    "--".as_ref(),
                    "/proc/self/fd/0".as_ref(),
                    target.as_os_str(),
                ],
                Some(identity.as_file()),
            )?;
            trusted_file(&target)?;
            ensure!(
                fs::read_to_string(&target)? == manifest.sha256,
                "face runtime identity changed during staging"
            );
            if fs::symlink_metadata("/usr/lib/security").is_err() {
                privileged(
                    "/usr/bin/install",
                    &[
                        "-d".as_ref(),
                        "-o".as_ref(),
                        "0".as_ref(),
                        "-g".as_ref(),
                        "0".as_ref(),
                        "-m".as_ref(),
                        "0755".as_ref(),
                        "--".as_ref(),
                        "/usr/lib/security".as_ref(),
                    ],
                )?;
            }
            trusted_directory(Path::new("/usr/lib/security"))?;
            ensure!(fs::symlink_metadata(BUNDLE_ROOT).is_err(),
                "face runtime destination appeared during deployment; refusing to overwrite it");
            privileged(
                "/usr/bin/mv",
                &[
                    "--no-clobber".as_ref(),
                    "-T".as_ref(),
                    "--".as_ref(),
                    unpacked.as_os_str(),
                    BUNDLE_ROOT.as_ref(),
                ],
            )?;
            ensure!(
                !unpacked.exists(),
                "face runtime destination changed during deployment"
            );
            installed_bundle(&manifest)
        })();
        let cleanup = privileged(
            "/usr/bin/rm",
            &["-r".as_ref(), "--".as_ref(), stage.as_os_str()],
        );
        result?;
        cleanup.context(
            "face runtime deployed, but root staging cleanup failed",
        )?;
        Ok(())
    }

    struct Installer {
        snapshot: PathBuf,
    }

    impl Installer {
        fn stage() -> anyhow::Result<Self> {
            use sha2::{Digest as _, Sha256};
            const SCRIPT: &str = include_str!("face_installer.py");
            deploy_bundle()?;
            // Root executes only an independently checked root-owned snapshot,
            // never the caller's temporary source or a downloaded shell script.
            trusted_directory(Path::new("/usr/lib"))?;
            let source_dir = tempfile::Builder::new()
                .prefix("rbw-face-source-")
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir_in("/tmp")?;
            let mut source =
                tempfile::NamedTempFile::new_in(source_dir.path())?;
            source.write_all(SCRIPT.as_bytes())?;
            source.flush()?;
            let output = privileged(
                "/usr/bin/mktemp",
                &[
                    "--".as_ref(),
                    "/usr/lib/.rbw-face-installer.XXXXXXXXXXXX".as_ref(),
                ],
            )?;
            let snapshot = std::str::from_utf8(&output.stdout)?.trim();
            let suffix = snapshot
                .strip_prefix("/usr/lib/.rbw-face-installer.")
                .context("unexpected installer staging path")?;
            ensure!(
                suffix.len() == 12
                    && suffix.bytes().all(|c| c.is_ascii_alphanumeric()),
                "unsafe installer staging path"
            );
            let installer = Self {
                snapshot: PathBuf::from(snapshot),
            };
            let result = (|| -> anyhow::Result<()> {
                privileged_input(
                    "/usr/bin/install",
                    &[
                        "-o".as_ref(),
                        "0".as_ref(),
                        "-g".as_ref(),
                        "0".as_ref(),
                        "-m".as_ref(),
                        "0644".as_ref(),
                        "--".as_ref(),
                        "/proc/self/fd/0".as_ref(),
                        installer.snapshot.as_os_str(),
                    ],
                    Some(source.as_file()),
                )?;
                trusted_file(&installer.snapshot)?;
                let file = open_regular(&installer.snapshot)?;
                let metadata = file.metadata()?;
                ensure!(
                    metadata.uid() == 0
                        && metadata.mode() & 0o7777 == 0o644
                        && metadata.nlink() == 1,
                    "unsafe root-owned installer snapshot"
                );
                let mut bytes = Vec::new();
                file.take(u64::try_from(SCRIPT.len())? + 1)
                    .read_to_end(&mut bytes)?;
                ensure!(Sha256::digest(&bytes) == Sha256::digest(SCRIPT.as_bytes()), "installer snapshot changed; refusing privileged execution");
                Ok(())
            })();
            if let Err(error) = result {
                installer.cleanup()?;
                return Err(error);
            }
            Ok(installer)
        }

        fn prepare(&self, user: &str, preview: &super::enrollment_preview::Preview) -> anyhow::Result<std::process::Output> {
            use std::os::fd::AsRawFd as _;
            use std::time::{Duration, Instant};

            use super::enrollment_preview;

            ensure!(!preview.cancelled(), "face enrollment was cancelled");
            let uid = rustix::process::geteuid().as_raw().to_string();
            let pid = std::process::id().to_string();
            let mut command = privileged_command(
                "/usr/lib/security/rbw-howdy/runtime/bin/python3",
                &[
                    "-I".as_ref(), "-B".as_ref(),
                    self.snapshot.as_os_str(), "prepare".as_ref(),
                    user.as_ref(), uid.as_ref(), pid.as_ref(),
                ],
            )?;
            // sudo reads passwords from /dev/tty, never from this EOF channel.
            let mut child = command.stdin(Stdio::piped()).stdout(Stdio::piped())
                .stderr(Stdio::inherit()).spawn()
                .context("cannot start controlled face enrollment")?;
            let mut stdout = child.stdout.take();
            let mut nonblocking = false;
            let mut exit_status = None;
            let mut result = (|| -> anyhow::Result<std::process::Output> {
                preview.bind_child_stdin(child.stdin.take().context("missing enrollment stdin")?);
                let stdout = stdout.as_mut().context("missing enrollment stdout")?;
                // SAFETY: stdout owns this live pipe descriptor. Preserve all
                // existing descriptor flags and only enable nonblocking reads.
                let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
                ensure!(flags >= 0, "cannot inspect enrollment pipe flags: {}", std::io::Error::last_os_error());
                let updated = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
                ensure!(updated >= 0, "cannot configure enrollment pipe: {}", std::io::Error::last_os_error());
                nonblocking = true;
                let mut protocol = enrollment_preview::Protocol::default();
                let mut buffer = [0_u8; 8192];
                let mut eof = false;
                let mut cancellation = None;
                loop {
                    let mut received = false;
                    if !eof {
                        match stdout.read(&mut buffer) {
                            Ok(0) => eof = true,
                            Ok(count) => {
                                protocol.feed(&buffer[..count], preview)?;
                                received = true;
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                            Err(error) => return Err(error).context("cannot read enrollment preview"),
                        }
                    }
                    if preview.cancelled() {
                        let since = cancellation.get_or_insert_with(Instant::now);
                        ensure!(since.elapsed() < Duration::from_secs(5),
                            "face enrollment did not stop after cancellation");
                    }
                    if exit_status.is_none() { exit_status = child.try_wait()?; }
                    if eof {
                        if let Some(status) = exit_status {
                            ensure!(!preview.cancelled(), "face enrollment was cancelled");
                            ensure!(status.success(), "face enrollment failed ({status})");
                            return Ok(std::process::Output {
                                status, stdout: protocol.finish()?, stderr: Vec::new(),
                            });
                        }
                    }
                    if !received { std::thread::sleep(Duration::from_millis(10)); }
                }
            })();
            // EOF gives the recorder its normal cancellation/rollback path.
            // Continue draining so a writer cannot block rollback on a full pipe.
            preview.close_stdin();
            drop(child.stdin.take());
            if result.is_err() {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    if let Some(status) = child.try_wait().ok().flatten() {
                        exit_status = Some(status);
                        break;
                    }
                    if !nonblocking || Instant::now() >= deadline {
                        // Let sudo forward termination to its supervised child;
                        // SIGKILLing only sudo can strand a privileged recorder.
                        let killed = if unsafe { libc::kill(i32::try_from(child.id())?, libc::SIGTERM) } == 0 {
                            Ok(())
                        } else {
                            Err(std::io::Error::last_os_error())
                        };
                        let waited = child.wait();
                        exit_status = Some(waited.context("cannot reap failed face enrollment")?);
                        if let Err(error) = killed {
                            if error.kind() != std::io::ErrorKind::InvalidInput {
                                return Err(error).context("cannot stop failed face enrollment");
                            }
                        }
                        break;
                    }
                    if let Some(stdout) = stdout.as_mut() {
                        let mut discard = [0_u8; 8192];
                        let _ = stdout.read(&mut discard);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            if preview.cancelled() && result.is_ok() {
                result = Err(anyhow::anyhow!("face enrollment was cancelled"));
            }
            // Root may have completed its transaction before a malformed
            // protocol line or a final Cancel was noticed by the display.
            if result.is_err() && exit_status.is_some_and(|status| status.success()) {
                self.invoke("rollback", user)
                    .context("face enrollment failed and completed enrollment rollback failed")?;
            }
            result
        }

        fn invoke(
            &self,
            action: &str,
            user: &str,
        ) -> anyhow::Result<std::process::Output> {
            let uid = rustix::process::geteuid().as_raw().to_string();
            let pid = std::process::id().to_string();
            privileged(
                "/usr/lib/security/rbw-howdy/runtime/bin/python3",
                &[
                    "-I".as_ref(),
                    "-B".as_ref(),
                    self.snapshot.as_os_str(),
                    action.as_ref(),
                    user.as_ref(),
                    uid.as_ref(),
                    pid.as_ref(),
                ],
            )
        }

        fn cleanup(self) -> anyhow::Result<()> {
            privileged(
                "/usr/bin/rm",
                &["--".as_ref(), self.snapshot.as_os_str()],
            )?;
            Ok(())
        }
    }

    fn optional_module(name: &str) -> anyhow::Result<Option<PathBuf>> {
        for directory in MODULE_DIRS {
            match fs::symlink_metadata(Path::new(directory).join(name)) {
                Ok(_) => return find_module(name).map(Some),
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .context("cannot inspect native PAM module")
                }
            }
        }
        Ok(None)
    }

    fn policy_text(howdy: &Path, permit: &Path) -> String {
        format!(
            "{MARKER}auth required {}\naccount required {}\n",
            howdy.display(),
            permit.display()
        )
    }

    fn find_module(name: &str) -> anyhow::Result<PathBuf> {
        for dir in MODULE_DIRS {
            let path = Path::new(dir).join(name);
            // A dangling symlink is not an absent module: reject it.
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    let path = trusted_file(&path)?;
                    let mut header = [0_u8; 18];
                    open_regular(&path)?
                        .read_exact(&mut header)
                        .with_context(|| {
                            format!(
                                "{} is not a native ELF PAM module",
                                path.display()
                            )
                        })?;
                    ensure!(
                        &header[..4] == b"\x7fELF"
                            && matches!(header[4], 1 | 2)
                            && match header[5] {
                                1 =>
                                    u16::from_le_bytes([
                                        header[16], header[17]
                                    ]) == 3,
                                2 =>
                                    u16::from_be_bytes([
                                        header[16], header[17]
                                    ]) == 3,
                                _ => false,
                            },
                        "{} is not a native ELF shared PAM module",
                        path.display()
                    );
                    return Ok(path);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("cannot inspect {}", path.display())
                    })
                }
            }
        }
        bail!("no {name} found in trusted system PAM module directories")
    }

    fn trusted_metadata(path: &Path) -> anyhow::Result<Metadata> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("cannot inspect {}", path.display()))?;
        ensure!(metadata.uid() == 0, "{} is not root-owned", path.display());
        // Symlink permissions are meaningless, but their owner and containing
        // directories must still be trusted. Canonical targets are checked too.
        ensure!(
            metadata.file_type().is_symlink() || metadata.mode() & 0o022 == 0,
            "{} is writable by non-root users",
            path.display()
        );
        Ok(metadata)
    }

    fn trusted_chain(path: &Path) -> anyhow::Result<()> {
        ensure!(path.is_absolute(), "trusted paths must be absolute");
        let mut current = PathBuf::new();
        for component in path.components() {
            current.push(component);
            trusted_metadata(&current)?;
        }
        Ok(())
    }

    fn trusted_directory(path: &Path) -> anyhow::Result<PathBuf> {
        trusted_chain(path)?;
        let canonical = fs::canonicalize(path)?;
        trusted_chain(&canonical)?;
        ensure!(
            fs::symlink_metadata(&canonical)?.is_dir(),
            "{} is not a directory",
            path.display()
        );
        Ok(canonical)
    }

    fn trusted_file(path: &Path) -> anyhow::Result<PathBuf> {
        trusted_chain(path)?;
        let canonical = fs::canonicalize(path)?;
        trusted_chain(&canonical)?;
        ensure!(
            fs::symlink_metadata(&canonical)?.is_file(),
            "{} is not a regular file",
            path.display()
        );
        Ok(canonical)
    }

    fn open_regular(path: &Path) -> anyhow::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("cannot open {}", path.display()))?;
        ensure!(
            file.metadata()?.is_file(),
            "{} is not a regular file",
            path.display()
        );
        Ok(file)
    }

    fn policy_contents() -> anyhow::Result<Option<String>> {
        trusted_directory(Path::new(PAM_DIR))?;
        match fs::symlink_metadata(POLICY) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(e) => return Err(e).context("cannot inspect rbw PAM policy"),
            Ok(metadata) => validate_policy_metadata(&metadata)?,
        }
        let file = open_regular(Path::new(POLICY))?;
        validate_policy_metadata(&file.metadata()?)?;
        let mut content = String::new();
        file.take(16 * 1024 + 1).read_to_string(&mut content)?;
        ensure!(content.len() <= 16 * 1024, "{POLICY} is too large; refusing to replace it");
        Ok(Some(content))
    }

    fn validate_policy_metadata(metadata: &Metadata) -> anyhow::Result<()> {
        ensure!(
            metadata.is_file(),
            "{POLICY} is not a regular file; refusing to replace it"
        );
        ensure!(
            metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o7777 == 0o644
                && metadata.nlink() == 1,
            "{POLICY} must be root:root, mode 0644, and not hard-linked"
        );
        Ok(())
    }

    fn policy_matches(expected: &str) -> anyhow::Result<bool> {
        let Some(content) = policy_contents()? else {
            return Ok(false);
        };
        ensure!(
            content == expected,
            "{POLICY} is not the exact policy managed by this setup; refusing to overwrite it. \
             Have an administrator inspect and explicitly remove/migrate the existing policy first"
        );
        Ok(true)
    }

    fn privileged(
        tool: &str,
        args: &[&std::ffi::OsStr],
    ) -> anyhow::Result<std::process::Output> {
        privileged_input(tool, args, None)
    }

    fn privileged_input(
        tool: &str,
        args: &[&std::ffi::OsStr],
        input: Option<&File>,
    ) -> anyhow::Result<std::process::Output> {
        let mut command = privileged_command(tool, args)?;
        // Use an already-open unprivileged descriptor. A source pathname could
        // otherwise be swapped for a root-only file before sudo opens it.
        let stdin = match input {
            Some(file) => {
                let mut input = file.try_clone()?;
                input.rewind()?;
                Stdio::from(input)
            }
            None => Stdio::inherit(),
        };
        let output = command
            .stdin(stdin)
            .stderr(Stdio::inherit())
            .output()
            .with_context(|| {
                format!("cannot execute controlled installation tool {tool}")
            })?;
        ensure!(output.status.success(), "{tool} failed ({})", output.status);
        Ok(output)
    }

    fn privileged_command(
        tool: &str,
        args: &[&std::ffi::OsStr],
    ) -> anyhow::Result<Command> {
        for directory in SYSTEM_PATH.split(':') {
            trusted_directory(Path::new(directory))?;
        }
        trusted_file(Path::new(tool))?;
        let mut command = if rustix::process::geteuid().is_root() {
            Command::new(tool)
        } else {
            trusted_file(Path::new("/usr/bin/sudo"))?;
            let mut command = Command::new("/usr/bin/sudo");
            command.arg("--").arg(tool);
            command
        };
        command.args(args).env_clear().env("PATH", SYSTEM_PATH);
        Ok(command)
    }

    fn install_policy(
        expected: &str,
        previous: Option<&str>,
        changed: &mut bool,
    ) -> anyhow::Result<()> {
        // The source lives in a private directory in the fixed system /tmp,
        // never TMPDIR. Even if the invoking user changes it concurrently, only
        // an independently verified root-owned snapshot is ever published.
        let tmp = fs::symlink_metadata("/tmp")?;
        ensure!(
            tmp.is_dir()
                && tmp.uid() == 0
                && (tmp.mode() & 0o022 == 0
                    || tmp.mode() & libc::S_ISVTX != 0),
            "/tmp must be a root-owned directory with sticky-bit protection"
        );
        let source_dir = tempfile::Builder::new()
            .prefix("rbw-setup-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp")?;
        let mut source = tempfile::NamedTempFile::new_in(source_dir.path())?;
        source.write_all(expected.as_bytes())?;
        source.flush()?;
        let uid = rustix::process::geteuid().as_raw();
        let dir_metadata = fs::symlink_metadata(source_dir.path())?;
        let source_metadata = source.as_file().metadata()?;
        ensure!(
            dir_metadata.is_dir()
                && dir_metadata.uid() == uid
                && dir_metadata.mode() & 0o7777 == 0o700
                && source_metadata.is_file()
                && source_metadata.uid() == uid
                && source_metadata.mode() & 0o7777 == 0o600
                && source_metadata.nlink() == 1,
            "unsafe temporary policy source"
        );
        trusted_directory(Path::new(PAM_DIR))?;
        let stage = privileged(
            "/usr/bin/mktemp",
            &["--".as_ref(), "/etc/pam.d/.rbw-setup.XXXXXXXXXXXX".as_ref()],
        )?;
        let stage =
            std::str::from_utf8(&stage.stdout)?.trim_end_matches('\n');
        let suffix = stage
            .strip_prefix("/etc/pam.d/.rbw-setup.")
            .context("mktemp returned an unexpected staging path")?;
        ensure!(
            suffix.len() == 12
                && suffix.bytes().all(|c| c.is_ascii_alphanumeric()),
            "mktemp returned an unsafe staging path"
        );
        let stage = Path::new(stage);
        let mut moved = false;
        let result = (|| -> anyhow::Result<()> {
            let metadata = fs::symlink_metadata(stage)?;
            ensure!(
                metadata.is_file()
                    && metadata.uid() == 0
                    && metadata.mode() & 0o7777 == 0o600
                    && metadata.nlink() == 1,
                "unsafe root-owned staging file"
            );
            privileged_input(
                "/usr/bin/install",
                &[
                    "-o".as_ref(),
                    "0".as_ref(),
                    "-g".as_ref(),
                    "0".as_ref(),
                    "-m".as_ref(),
                    "0644".as_ref(),
                    "--".as_ref(),
                    "/proc/self/fd/0".as_ref(),
                    stage.as_os_str(),
                ],
                Some(source.as_file()),
            )?;
            trusted_file(stage)?;
            let file = open_regular(stage)?;
            let metadata = file.metadata()?;
            ensure!(
                metadata.uid() == 0
                    && metadata.gid() == 0
                    && metadata.mode() & 0o7777 == 0o644
                    && metadata.nlink() == 1,
                "unsafe installed policy snapshot"
            );
            let mut snapshot = String::new();
            file.take(16 * 1024).read_to_string(&mut snapshot)?;
            ensure!(snapshot == expected, "temporary policy changed during installation; refusing to publish");
            trusted_directory(Path::new(PAM_DIR))?;
            // Recheck the full trusted snapshot immediately before publishing.
            // A legacy migration atomically replaces only the recognized old
            // policy, after enrollment and ordinary-user camera access succeed.
            let current = policy_contents()?;
            ensure!(
                current.as_deref() == previous,
                "{POLICY} changed during setup; refusing to overwrite it"
            );
            if previous.is_some() {
                privileged(
                    "/usr/bin/mv",
                    &[
                        "-T".as_ref(),
                        "--".as_ref(),
                        stage.as_os_str(),
                        POLICY.as_ref(),
                    ],
                )?;
                moved = true;
            } else {
                // No overwrite, including a policy appearing after preflight.
                privileged(
                    "/usr/bin/ln",
                    &[
                        "-T".as_ref(),
                        "--".as_ref(),
                        stage.as_os_str(),
                        POLICY.as_ref(),
                    ],
                )?;
            }
            *changed = true;
            Ok(())
        })();
        // Never recursively delete a path and never act on unvalidated output.
        // The random staging path is confined to the trusted PAM directory.
        let cleanup = if moved {
            Ok(())
        } else {
            privileged("/usr/bin/rm", &["--".as_ref(), stage.as_os_str()])
                .map(|_| ())
        };
        result?;
        cleanup.context(
            "policy installed, but root-owned staging-file cleanup failed",
        )?;
        ensure!(policy_matches(expected)?, "installed policy is missing");
        Ok(())
    }
}
