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

/// State of the Inspect screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectState {
    /// Job that feeds this screen; results of other jobs are ignored.
    pub job: JobId,
    /// Where the job stands.
    pub phase: Phase,
}

impl InspectState {
    /// A screen waiting for job `job`.
    #[must_use]
    pub fn loading(job: JobId) -> Self {
        Self {
            job,
            phase: Phase::Loading,
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
