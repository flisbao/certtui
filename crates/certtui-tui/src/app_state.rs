//! The data behind every screen.

use std::sync::Arc;
use std::time::Instant;

use certtui_domain::model::{FingerprintFormat, InspectionReport};
use certtui_domain::target::Target;

use crate::theme::ThemeKind;
use crate::toast::Toast;

/// Identifier of a background job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct JobId(pub u64);

/// Top-level screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Target input and recent targets.
    Home,
    /// Chain tree and detail tabs of one target.
    Inspect,
}

/// A dialog drawn over the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modal {
    /// Key reference.
    Help,
}

/// State of the Home screen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HomeState {
    /// Text typed so far.
    pub input: String,
    /// Cursor position inside `input`, in characters.
    pub cursor: usize,
    /// Whether keys type into `input` instead of acting as commands.
    pub editing: bool,
    /// Recent targets (filled from the history in a later milestone).
    pub recents: Vec<String>,
    /// Favorite targets (filled from the history in a later milestone).
    pub favorites: Vec<String>,
    /// Selected row of the recents and favorites list.
    pub selected: Option<usize>,
}

/// Where an inspect job stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    /// The job is running.
    Loading,
    /// The job produced a report.
    Ready(Arc<InspectionReport>),
    /// The job failed; the message is user-facing.
    Failed(String),
}

/// A tab of the details pane.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Tab {
    /// Subject, issuer, validity and the short SHA-256.
    #[default]
    Overview,
    /// Subject and issuer names.
    SubjectIssuer,
    /// Subject alternative names.
    Sans,
    /// Key usage, identifiers and the extension list.
    Extensions,
    /// SHA-1, SHA-256 and SHA-512.
    Fingerprints,
    /// Revocation status.
    Revocation,
    /// Lint findings.
    Findings,
    /// The certificate as PEM.
    Raw,
}

impl Tab {
    /// Every tab, in display order.
    pub const ALL: [Tab; 8] = [
        Tab::Overview,
        Tab::SubjectIssuer,
        Tab::Sans,
        Tab::Extensions,
        Tab::Fingerprints,
        Tab::Revocation,
        Tab::Findings,
        Tab::Raw,
    ];

    /// Name shown in the tab bar.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::SubjectIssuer => "Subject/Issuer",
            Tab::Sans => "SANs",
            Tab::Extensions => "Extensions",
            Tab::Fingerprints => "Fingerprints",
            Tab::Revocation => "Revocation",
            Tab::Findings => "Findings",
            Tab::Raw => "Raw",
        }
    }

    fn position(self) -> usize {
        Self::ALL.iter().position(|tab| *tab == self).unwrap_or(0)
    }

    /// The tab to the right, wrapping around.
    #[must_use]
    pub fn next(self) -> Tab {
        Self::ALL
            .get((self.position() + 1) % Self::ALL.len())
            .copied()
            .unwrap_or_default()
    }

    /// The tab to the left, wrapping around.
    #[must_use]
    pub fn prev(self) -> Tab {
        Self::ALL
            .get((self.position() + Self::ALL.len() - 1) % Self::ALL.len())
            .copied()
            .unwrap_or_default()
    }
}

/// Which pane of the Inspect screen has focus.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Pane {
    /// The chain tree.
    #[default]
    Chain,
    /// The detail rows.
    Details,
}

/// State of the Inspect screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectState {
    /// Job that feeds this screen; results of other jobs are ignored.
    pub job: JobId,
    /// Where the job stands.
    pub phase: Phase,
    /// Index of the selected certificate in the chain.
    pub selected_cert: usize,
    /// Visible tab.
    pub tab: Tab,
    /// Pane with focus.
    pub pane: Pane,
    /// Row under the cursor in the details pane.
    pub row_cursor: usize,
    /// First visible row of the details pane.
    pub scroll: u16,
}

impl InspectState {
    /// A screen waiting for job `job`.
    #[must_use]
    pub fn loading(job: JobId) -> Self {
        Self {
            job,
            phase: Phase::Loading,
            selected_cert: 0,
            tab: Tab::default(),
            pane: Pane::default(),
            row_cursor: 0,
            scroll: 0,
        }
    }

    /// The report, once the job finished successfully.
    #[must_use]
    pub fn report(&self) -> Option<&Arc<InspectionReport>> {
        match &self.phase {
            Phase::Ready(report) => Some(report),
            Phase::Loading | Phase::Failed(_) => None,
        }
    }
}

/// Bookkeeping of running jobs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobTracker {
    next: u64,
    active: Vec<JobId>,
}

impl JobTracker {
    /// Registers a new job and returns its id.
    pub fn start(&mut self) -> JobId {
        let id = JobId(self.next);
        self.next = self.next.saturating_add(1);
        self.active.push(id);
        id
    }

    /// Forgets a job; returns whether it was active.
    pub fn finish(&mut self, id: JobId) -> bool {
        let before = self.active.len();
        self.active.retain(|active| *active != id);
        self.active.len() != before
    }

    /// Whether any job is running.
    #[must_use]
    pub fn any_active(&self) -> bool {
        !self.active.is_empty()
    }

    /// Whether `id` is running.
    #[must_use]
    pub fn is_active(&self, id: JobId) -> bool {
        self.active.contains(&id)
    }
}

/// Turns text typed on Home into a target, or a user-facing error.
///
/// Injected so `update` stays free of file system access.
pub type TargetParser = fn(&str) -> Result<Target, String>;

/// Everything the views draw and `update` changes.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Current screen.
    pub screen: Screen,
    /// Home screen data.
    pub home: HomeState,
    /// Inspect screen data, when a target was opened.
    pub inspect: Option<InspectState>,
    /// Dialog over the screen.
    pub modal: Option<Modal>,
    /// Transient message.
    pub toast: Option<Toast>,
    /// Running jobs.
    pub jobs: JobTracker,
    /// Active theme.
    pub theme: ThemeKind,
    /// Format of the fingerprints shown and copied.
    pub fingerprint_format: FingerprintFormat,
    /// Terminal size as `(columns, rows)`.
    pub size: (u16, u16),
    /// Last clock reading received through `Msg::Tick`.
    pub now: Instant,
    /// Whether the main loop must end.
    pub should_quit: bool,
    /// How text typed on Home becomes a target.
    pub target_parser: TargetParser,
}

impl AppState {
    /// Shows `toast` in place of any earlier one.
    pub fn set_toast(&mut self, toast: Toast) {
        self.toast = Some(toast);
    }

    /// A fresh state on the Home screen.
    #[must_use]
    pub fn new(now: Instant) -> Self {
        Self {
            screen: Screen::Home,
            home: HomeState::default(),
            inspect: None,
            modal: None,
            toast: None,
            jobs: JobTracker::default(),
            theme: ThemeKind::default(),
            fingerprint_format: FingerprintFormat::default(),
            size: (80, 24),
            now,
            should_quit: false,
            target_parser: crate::update_home::default_target_parser,
        }
    }
}
