//! Which sinks to use, from the `ui.clipboard` setting and the environment.

use std::collections::HashMap;
use std::io::Write;
use std::str::FromStr;

use thiserror::Error;

use super::{ClipboardSink, CopyMethod, Osc52Sink};

/// Whether the native clipboard is part of this build.
pub const NATIVE_COMPILED: bool = cfg!(feature = "native-clipboard");

/// The `ui.clipboard` setting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ClipboardStrategy {
    /// OSC 52 over SSH; the native clipboard first (then OSC 52) when local.
    #[default]
    Auto,
    /// OSC 52 only.
    Osc52,
    /// The native clipboard only.
    Native,
    /// OSC 52, then the native clipboard.
    Osc52ThenNative,
    /// Copying is disabled.
    Off,
}

/// A clipboard setting that cannot be honored.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ClipboardConfigError {
    /// The value is not one of the known strategies.
    #[error("unknown clipboard strategy `{0}`; use auto, osc52, native, osc52,native or off")]
    Unknown(String),
    /// The strategy needs the native clipboard, which this build lacks.
    #[error("the native clipboard is not compiled in; rebuild with the `native-clipboard` feature")]
    NativeNotCompiled,
}

impl FromStr for ClipboardStrategy {
    type Err = ClipboardConfigError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "auto" => Ok(Self::Auto),
            "osc52" => Ok(Self::Osc52),
            "native" => Ok(Self::Native),
            "osc52,native" => Ok(Self::Osc52ThenNative),
            "off" => Ok(Self::Off),
            other => Err(ClipboardConfigError::Unknown(
                other.chars().take(40).collect(),
            )),
        }
    }
}

/// The few environment variables the strategy looks at, injectable for tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvView(HashMap<String, String>);

impl EnvView {
    /// A view over the given variables.
    #[must_use]
    pub fn from_pairs<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        Self(
            pairs
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect(),
        )
    }

    /// The variables of this process.
    #[must_use]
    pub fn from_process() -> Self {
        let pairs = ["SSH_CONNECTION", "SSH_TTY", "TMUX"]
            .into_iter()
            .filter_map(|key| std::env::var(key).ok().map(|value| (key.to_owned(), value)));
        Self(pairs.collect())
    }

    fn is_set(&self, key: &str) -> bool {
        self.0.get(key).is_some_and(|value| !value.is_empty())
    }

    /// Whether the session runs over SSH.
    #[must_use]
    pub fn is_ssh(&self) -> bool {
        self.is_set("SSH_CONNECTION") || self.is_set("SSH_TTY")
    }

    /// Whether the session runs inside tmux.
    ///
    /// OSC 52 is sent as it is, without tmux's DCS passthrough: tmux needs
    /// `set -g set-clipboard on` to forward it.
    #[must_use]
    pub fn is_tmux(&self) -> bool {
        self.is_set("TMUX")
    }
}

/// The methods `strategy` tries, in order.
///
/// # Errors
///
/// [`ClipboardConfigError::NativeNotCompiled`] when an explicit strategy needs
/// the native clipboard and the build lacks it. `Auto` just skips it.
pub fn plan_methods(
    strategy: ClipboardStrategy,
    env: &EnvView,
) -> Result<Vec<CopyMethod>, ClipboardConfigError> {
    let needs_native = matches!(
        strategy,
        ClipboardStrategy::Native | ClipboardStrategy::Osc52ThenNative
    );
    if needs_native && !NATIVE_COMPILED {
        return Err(ClipboardConfigError::NativeNotCompiled);
    }
    let mut methods = match strategy {
        ClipboardStrategy::Off => Vec::new(),
        ClipboardStrategy::Osc52 => vec![CopyMethod::Osc52],
        ClipboardStrategy::Native => vec![CopyMethod::Native],
        ClipboardStrategy::Osc52ThenNative => vec![CopyMethod::Osc52, CopyMethod::Native],
        ClipboardStrategy::Auto if env.is_ssh() => vec![CopyMethod::Osc52, CopyMethod::Native],
        ClipboardStrategy::Auto => vec![CopyMethod::Native, CopyMethod::Osc52],
    };
    if !NATIVE_COMPILED {
        methods.retain(|method| *method != CopyMethod::Native);
    }
    Ok(methods)
}

/// The sinks for `strategy`, in the order they are tried. OSC 52 goes to `osc52_out`.
///
/// # Errors
///
/// See [`plan_methods`].
pub fn build_sinks(
    strategy: ClipboardStrategy,
    env: &EnvView,
    osc52_out: impl Write + Send + 'static,
) -> Result<Vec<Box<dyn ClipboardSink>>, ClipboardConfigError> {
    let mut osc52_out = Some(osc52_out);
    let mut sinks: Vec<Box<dyn ClipboardSink>> = Vec::new();
    for method in plan_methods(strategy, env)? {
        match method {
            CopyMethod::Osc52 => {
                if let Some(out) = osc52_out.take() {
                    sinks.push(Box::new(Osc52Sink::new(out)));
                }
            }
            CopyMethod::Native => {
                #[cfg(feature = "native-clipboard")]
                sinks.push(Box::new(super::NativeSink::new()));
            }
        }
    }
    Ok(sinks)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssh() -> EnvView {
        EnvView::from_pairs([("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 55000")])
    }

    #[test]
    fn quando_auto_e_ssh_deve_ordenar_osc52_primeiro() {
        let methods = plan_methods(ClipboardStrategy::Auto, &ssh()).unwrap();
        assert_eq!(methods.first(), Some(&CopyMethod::Osc52));
        let tty = EnvView::from_pairs([("SSH_TTY", "/dev/pts/3")]);
        let methods = plan_methods(ClipboardStrategy::Auto, &tty).unwrap();
        assert_eq!(methods.first(), Some(&CopyMethod::Osc52));
    }

    #[cfg(feature = "native-clipboard")]
    #[test]
    fn quando_auto_e_local_deve_ordenar_native_depois_osc52() {
        let methods = plan_methods(ClipboardStrategy::Auto, &EnvView::default()).unwrap();
        assert_eq!(methods, [CopyMethod::Native, CopyMethod::Osc52]);
    }

    #[cfg(not(feature = "native-clipboard"))]
    #[test]
    fn quando_auto_e_local_sem_native_deve_usar_so_osc52() {
        let methods = plan_methods(ClipboardStrategy::Auto, &EnvView::default()).unwrap();
        assert_eq!(methods, [CopyMethod::Osc52]);
    }

    #[test]
    fn quando_ssh_vazio_deve_contar_como_local() {
        let env = EnvView::from_pairs([("SSH_CONNECTION", ""), ("SSH_TTY", "")]);
        assert!(!env.is_ssh());
    }

    #[test]
    fn quando_off_deve_nao_ter_sinks_e_erro_unavailable() {
        let sinks = build_sinks(ClipboardStrategy::Off, &EnvView::default(), Vec::new()).unwrap();
        assert!(sinks.is_empty());
        let fallback = crate::clipboard::FallbackSink::new(sinks);
        assert!(matches!(
            fallback.copy("x"),
            Err(crate::clipboard::ClipboardError::Unavailable(_))
        ));
    }

    #[test]
    fn quando_osc52_deve_ter_um_sink_que_escreve_no_destino() {
        let sinks = build_sinks(ClipboardStrategy::Osc52, &EnvView::default(), Vec::new()).unwrap();
        assert_eq!(sinks.len(), 1);
    }

    #[cfg(not(feature = "native-clipboard"))]
    #[test]
    fn quando_estrategia_e_native_sem_feature_deve_dar_native_not_compiled() {
        for strategy in [
            ClipboardStrategy::Native,
            ClipboardStrategy::Osc52ThenNative,
        ] {
            assert_eq!(
                plan_methods(strategy, &EnvView::default()),
                Err(ClipboardConfigError::NativeNotCompiled)
            );
        }
    }

    #[cfg(feature = "native-clipboard")]
    #[test]
    fn quando_estrategia_e_native_com_feature_deve_ter_um_sink_native() {
        let sinks =
            build_sinks(ClipboardStrategy::Native, &EnvView::default(), Vec::new()).unwrap();
        assert_eq!(sinks.len(), 1);
        let both = plan_methods(ClipboardStrategy::Osc52ThenNative, &EnvView::default()).unwrap();
        assert_eq!(both, [CopyMethod::Osc52, CopyMethod::Native]);
    }

    #[test]
    fn quando_estrategia_string_valida_deve_parsear() {
        assert_eq!("auto".parse(), Ok(ClipboardStrategy::Auto));
        assert_eq!("osc52".parse(), Ok(ClipboardStrategy::Osc52));
        assert_eq!("native".parse(), Ok(ClipboardStrategy::Native));
        assert_eq!(
            "osc52,native".parse(),
            Ok(ClipboardStrategy::Osc52ThenNative)
        );
        assert_eq!("off".parse(), Ok(ClipboardStrategy::Off));
    }

    #[test]
    fn quando_estrategia_string_invalida_deve_dar_erro() {
        let error = "clipboard".parse::<ClipboardStrategy>().unwrap_err();
        assert_eq!(error, ClipboardConfigError::Unknown("clipboard".to_owned()));
        let long = "x".repeat(500).parse::<ClipboardStrategy>().unwrap_err();
        assert!(long.to_string().len() < 200, "{long}");
    }

    #[test]
    fn quando_tmux_definido_deve_ser_reconhecido_sem_mudar_a_ordem() {
        let env = EnvView::from_pairs([("TMUX", "/tmp/tmux-1000/default,1,0")]);
        assert!(env.is_tmux());
        assert_eq!(
            plan_methods(ClipboardStrategy::Osc52, &env),
            Ok(vec![CopyMethod::Osc52])
        );
    }
}
