use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::util::expand_tilde;

const SAMPLE_CONFIG: &str = include_str!("../jaiba_config.toml.sample");

/// Explicit, non-secret hardware identity. Both fields are required: no auto-selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct YubikeyConfig {
    pub slot: u8,
    pub serial: u32,
}

impl YubikeyConfig {
    pub fn validate(self) -> anyhow::Result<Self> {
        anyhow::ensure!(matches!(self.slot, 1 | 2), "yubikey.slot must be 1 or 2");
        anyhow::ensure!(self.serial != 0, "yubikey.serial must be a nonzero u32");
        Ok(self)
    }
}

pub struct Config {
    pub default_database: Option<PathBuf>,
    pub keyfile: Option<PathBuf>,
    pub yubikey: Option<YubikeyConfig>,
    pub auto_lock: Duration,
    pub clipboard_timeout: Duration,
    pub theme: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_database: None,
            keyfile: None,
            yubikey: None,
            auto_lock: Duration::from_secs(300),
            clipboard_timeout: Duration::from_secs(15),
            theme: None,
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    default_database: Option<String>,
    keyfile: Option<String>,
    yubikey: Option<YubikeyConfig>,
    auto_lock: Option<u64>,
    clipboard_timeout: Option<u64>,
    theme: Option<String>,
}

pub fn load_config() -> anyhow::Result<Config> {
    let path = expand_tilde("~/.config/rama/jaiba_config.toml");

    if !path.is_file() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("couldn't create {}", parent.display()))?;
        }

        fs::write(&path, SAMPLE_CONFIG)
            .with_context(|| format!("couldn't write {}", path.display()))?;
    }

    let text =
        fs::read_to_string(&path).with_context(|| format!("couldn't read {}", path.display()))?;
    parse_config(&text)
}

fn parse_config(text: &str) -> anyhow::Result<Config> {
    let raw: ConfigFile = toml::from_str(text)?;

    let defaults = Config::default();

    Ok(Config {
        default_database: raw.default_database.map(|s| expand_tilde(&s)),
        keyfile: raw.keyfile.map(|s| expand_tilde(&s)),
        yubikey: raw.yubikey.map(YubikeyConfig::validate).transpose()?,
        auto_lock: raw
            .auto_lock
            .map(Duration::from_secs)
            .unwrap_or(defaults.auto_lock),
        clipboard_timeout: raw
            .clipboard_timeout
            .map(Duration::from_secs)
            .unwrap_or(defaults.clipboard_timeout),
        theme: raw.theme,
    })
}

#[derive(Serialize)]
struct ConfigFileOut<'a> {
    default_database: Option<String>,
    keyfile: Option<String>,
    yubikey: Option<YubikeyConfig>,
    auto_lock: u64,
    clipboard_timeout: u64,
    theme: Option<&'a str>,
}

pub fn save_config(config: &Config) -> anyhow::Result<()> {
    let path = expand_tilde("~/.config/rama/jaiba_config.toml");

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("couldn't create {}", parent.display()))?;
    }

    let text = serialize_config(config)?;

    fs::write(&path, text).with_context(|| format!("couldn't write {}", path.display()))?;

    Ok(())
}

fn serialize_config(config: &Config) -> anyhow::Result<String> {
    let out = ConfigFileOut {
        default_database: config
            .default_database
            .as_ref()
            .map(|p| p.display().to_string()),
        keyfile: config.keyfile.as_ref().map(|p| p.display().to_string()),
        yubikey: config.yubikey.map(YubikeyConfig::validate).transpose()?,
        auto_lock: config.auto_lock.as_secs(),
        clipboard_timeout: config.clipboard_timeout.as_secs(),
        theme: config.theme.as_deref(),
    };

    toml::to_string_pretty(&out).context("couldn't serialize config")
}

#[cfg(test)]
mod tests {
    use super::{Config, parse_config, serialize_config};
    use std::path::PathBuf;

    #[test]
    fn yubikey_config_rejects_partial_invalid_or_misspelled_selection() {
        for text in [
            "[yubikey]",
            "[yubikey]\nslot = 2",
            "[yubikey]\nserial = 39269826",
            "[yubikey]\nslot = 0\nserial = 39269826",
            "[yubikey]\nslot = 3\nserial = 39269826",
            "[yubikey]\nslot = 2\nserial = 0",
            "[yubikey]\nslot = 2\nserial = -1",
            "[yubikey]\nslot = 2\nserial = 4294967296",
            "[yubikey]\nslot = 2\nserial = 39269826\nenabled = false",
            "[yubikey]\nslot = \"2\"\nserial = 39269826",
            "[yubikeys]\nslot = 2\nserial = 39269826",
        ] {
            assert!(parse_config(text).is_err(), "must reject {text:?}");
        }
    }

    #[test]
    fn malformed_config_aborts_startup_before_clipboard_or_runtime_services() {
        let dir = std::env::temp_dir().join(format!("jaiba-invalid-config-{}", std::process::id()));
        std::fs::create_dir_all(dir.join(".config/rama")).unwrap();
        std::fs::write(
            dir.join(".config/rama/jaiba_config.toml"),
            "[yubikey]\nslot = 2",
        )
        .unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "config::tests::startup_config_child",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env("HOME", &dir)
            .env_remove("XDG_RUNTIME_DIR")
            .env("JAIBA_CLIPBOARD_BACKEND", "invalid-test-sentinel")
            .env("JAIBA_CONFIG_CHILD", "1")
            .output()
            .unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    #[test]
    #[ignore = "subprocess-only config startup probe"]
    fn startup_config_child() {
        assert_eq!(std::env::var("JAIBA_CONFIG_CHILD").as_deref(), Ok("1"));
        let mut terminal = ratatui::Terminal::with_options(
            ratatui::backend::CrosstermBackend::new(std::io::stdout()),
            ratatui::TerminalOptions {
                viewport: ratatui::Viewport::Fixed(ratatui::layout::Rect::new(0, 0, 80, 24)),
            },
        )
        .unwrap();
        let err = crate::app::run(&mut terminal, false).unwrap_err();
        assert!(
            err.to_string().contains("config"),
            "must surface invalid config, got {err}"
        );
    }

    #[test]
    fn parses_optional_keyfile_path() {
        let config = parse_config(
            r#"
                default_database = "/tmp/passwords.kdbx"
                keyfile = "/tmp/passwords.keyx"
            "#,
        )
        .expect("config should parse");

        assert_eq!(
            config.default_database,
            Some(PathBuf::from("/tmp/passwords.kdbx"))
        );
        assert_eq!(config.keyfile, Some(PathBuf::from("/tmp/passwords.keyx")));
    }

    #[test]
    fn keyfile_remains_optional() {
        let config = parse_config("default_database = \"/tmp/passwords.kdbx\"")
            .expect("config should parse");

        assert_eq!(config.keyfile, None);

        let text = serialize_config(&config).expect("config should serialize");
        assert!(!text.contains("keyfile"));
    }

    #[test]
    fn serializes_keyfile_path() {
        let config = Config {
            keyfile: Some(PathBuf::from("/tmp/passwords.keyx")),
            ..Config::default()
        };

        let text = serialize_config(&config).expect("config should serialize");
        assert!(text.contains("keyfile = \"/tmp/passwords.keyx\""));
    }

    #[test]
    fn saving_other_preferences_retains_complete_hardware_selection() {
        let mut config = parse_config("[yubikey]\nslot = 2\nserial = 39269826").unwrap();
        config.theme = Some("synthetic-theme".into());
        config.keyfile = Some(PathBuf::from("synthetic.key"));
        let serialized = serialize_config(&config).unwrap();
        let reloaded = parse_config(&serialized).unwrap();
        assert_eq!(reloaded.yubikey, config.yubikey);
        assert_eq!(reloaded.keyfile, config.keyfile);
        assert_eq!(reloaded.theme, config.theme);
    }
}
