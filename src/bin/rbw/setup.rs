//! Read-only preflight and narrowly scoped installation of rbw's own PAM policy.

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn run(apply: bool) -> anyhow::Result<()> {
    linux::run(apply)
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub fn run(_apply: bool) -> anyhow::Result<()> {
    anyhow::bail!(
        "face setup requires GNU/Linux and the native Howdy pam_howdy.so module"
    )
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod linux {
    use std::fs::{self, File, Metadata, OpenOptions};
    use std::io::{Read as _, Write as _};
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
    const SYSTEM_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
    // Only distro-controlled system locations, never Homebrew, PATH, an
    // environment override, or a user-supplied module name.
    const MODULE_DIRS: &[&str] = &[
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

    pub(super) fn run(apply: bool) -> anyhow::Result<()> {
        guidance();
        let howdy = find_module("pam_howdy.so").context(
            "install native Howdy (pam_howdy.so) using your distro's instructions; \
             legacy Python PAM shims and fingerprint fallbacks are not supported",
        )?;
        let permit = find_module("pam_permit.so")
            .context("install your distro's system PAM modules package")?;
        println!("Trusted native Howdy module: {}", howdy.display());
        let policy = policy_text(&howdy, &permit);
        trusted_directory(Path::new(PAM_DIR))?;
        let installed = policy_matches(&policy)?;
        if !installed && !apply {
            bail!(
                "{POLICY} is not installed; after Howdy setup, run `rbw setup --apply` \
                 to authorize installation of this isolated policy"
            );
        }
        if !installed {
            install_policy(&policy)?;
        }
        println!("Configuration ready: {POLICY} (face only; no password fallback).");
        println!(
            "Hardware authentication NOT VERIFIED: camera configuration, runtime \
             access, Howdy model files and enrollment are not checked by setup."
        );
        println!(
            "Verify real face success, rejection and cancellation through a normal \
             protected rbw command in your local graphical session after a master-password unlock."
        );
        Ok(())
    }

    fn guidance() {
        println!("rbw setup checks configuration only; it never authenticates or accesses the vault.");
        println!("1. Install native Howdy for your distro: https://github.com/boltgolt/howdy");
        println!(
            "   Keep sudo/login PAM stacks unchanged; rbw uses only {POLICY}. \
             Review any global PAM changes made by the distro's Howdy installer."
        );
        println!(
            "2. Configure the IR camera/device and required model files using Howdy's \
             own instructions (`sudo howdy config`); verify camera permissions for \
             your ordinary, non-root rbw-agent user. Never run rbw-agent as root."
        );
        let user = login_user();
        println!(
            "3. Enroll your actual login user: sudo howdy -U {user} add"
        );
        println!("   Camera diagnostic only: sudo howdy -U {user} test (not proof of rbw PAM authentication).");
        println!("4. Run rbw setup --apply, then rbw setup --check (both leave hardware unverified).");
    }

    fn login_user() -> String {
        // Do not trust USER/LOGNAME/SUDO_USER for enrollment guidance. A root
        // invocation cannot infer the intended non-root account reliably.
        if rustix::process::geteuid().is_root() {
            return "<your-login-user>".to_owned();
        }
        let result = trusted_file(Path::new("/usr/bin/id")).and_then(|_| {
            Command::new("/usr/bin/id")
                .arg("-un")
                .env_clear()
                .env("PATH", SYSTEM_PATH)
                .output()
                .context("failed to resolve login user")
        });
        if let Ok(output) = result {
            if output.status.success() {
                if let Ok(name) = std::str::from_utf8(&output.stdout) {
                    let name = name.trim();
                    if !name.is_empty()
                        && name.bytes().all(|c| {
                            c.is_ascii_alphanumeric() || b"_-.".contains(&c)
                        })
                    {
                        return format!("'{name}'");
                    }
                }
            }
        }
        "<your-login-user>".to_owned()
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

    fn policy_matches(expected: &str) -> anyhow::Result<bool> {
        match fs::symlink_metadata(POLICY) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(false)
            }
            Err(e) => return Err(e).context("cannot inspect rbw PAM policy"),
            Ok(metadata) => {
                ensure!(
                    metadata.is_file(),
                    "{POLICY} is not a regular file; refusing to replace it"
                );
                ensure!(
                    metadata.uid() == 0 && metadata.mode() & 0o7777 == 0o644 && metadata.nlink() == 1,
                    "{POLICY} must be root-owned, mode 0644, and not hard-linked"
                );
            }
        }
        let file = open_regular(Path::new(POLICY))?;
        let mut content = String::new();
        file.take(16 * 1024).read_to_string(&mut content)?;
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
        trusted_file(Path::new(tool))?;
        let mut command = if rustix::process::geteuid().is_root() {
            Command::new(tool)
        } else {
            trusted_file(Path::new("/usr/bin/sudo"))?;
            let mut command = Command::new("/usr/bin/sudo");
            command.arg("--").arg(tool);
            command
        };
        let output = command
            .args(args)
            .env_clear()
            .env("PATH", SYSTEM_PATH)
            .stdin(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .with_context(|| {
                format!("cannot execute controlled installation tool {tool}")
            })?;
        ensure!(output.status.success(), "{tool} failed ({})", output.status);
        Ok(output)
    }

    fn install_policy(expected: &str) -> anyhow::Result<()> {
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
        let result = (|| -> anyhow::Result<()> {
            let metadata = fs::symlink_metadata(stage)?;
            ensure!(
                metadata.is_file()
                    && metadata.uid() == 0
                    && metadata.mode() & 0o7777 == 0o600
                    && metadata.nlink() == 1,
                "unsafe root-owned staging file"
            );
            privileged(
                "/usr/bin/install",
                &[
                    "-o".as_ref(),
                    "0".as_ref(),
                    "-g".as_ref(),
                    "0".as_ref(),
                    "-m".as_ref(),
                    "0644".as_ref(),
                    "--".as_ref(),
                    source.path().as_os_str(),
                    stage.as_os_str(),
                ],
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
            // No overwrite, including symlinks or a policy installed by another
            // process after preflight. Only root can change either link parent.
            if policy_matches(expected)? {
                return Ok(());
            }
            privileged(
                "/usr/bin/ln",
                &[
                    "-T".as_ref(),
                    "--".as_ref(),
                    stage.as_os_str(),
                    POLICY.as_ref(),
                ],
            )?;
            Ok(())
        })();
        // Never recursively delete a path and never act on unvalidated output.
        // The random staging path is confined to the trusted PAM directory.
        let cleanup =
            privileged("/usr/bin/rm", &["--".as_ref(), stage.as_os_str()]);
        result?;
        cleanup.context(
            "policy installed, but root-owned staging-file cleanup failed",
        )?;
        ensure!(policy_matches(expected)?, "installed policy is missing");
        Ok(())
    }
}
