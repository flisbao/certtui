//! The data behind every screen.

use std::sync::Arc;
use std::time::Instant;

use certtui_app::export::{ExportFormat, ExportSelection};
use certtui_app::history::History;
use certtui_domain::batch_row::BatchRow;
use certtui_domain::limits::Limits;
use certtui_domain::model::{FingerprintFormat, InspectionReport};
use certtui_domain::target::{NetworkTarget, Target};
use certtui_domain::time::Timestamp;

use zeroize::Zeroizing;

use crate::msg::{ExportRequest, Password};
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
    /// Table of a batch run.
    Batch,
}

/// What is typed into the password dialog: shown as dots, wiped when dropped,
/// never printed by `Debug`.
#[derive(Clone)]
pub struct Masked(Zeroizing<String>);

impl Masked {
    /// An empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self(Zeroizing::new(String::new()))
    }

    /// Appends a typed character.
    pub fn push(&mut self, c: char) {
        self.0.push(c);
    }

    /// Removes the last character.
    pub fn pop(&mut self) {
        self.0.pop();
    }

    /// Number of characters typed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.chars().count()
    }

    /// Whether nothing was typed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The typed text as a secret, ready to send.
    #[must_use]
    pub fn to_password(&self) -> Password {
        Password::new(certtui_app::keystore::SecretString::from(
            self.0.to_string(),
        ))
    }
}

impl Default for Masked {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Masked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Masked({} chars)", self.len())
    }
}

/// The keystore password dialog.
#[derive(Debug, Clone)]
pub struct PasswordModal {
    /// What was being opened.
    pub target: Target,
    /// What the user typed so far.
    pub input: Masked,
    /// Why the last attempt failed.
    pub error: Option<String>,
}

/// The export dialog.
#[derive(Debug, Clone)]
pub struct ExportModal {
    /// The report whose certificates are exported.
    pub report: Arc<InspectionReport>,
    /// File format.
    pub format: ExportFormat,
    /// Which certificates.
    pub selection: ExportSelection,
    /// The certificate that was selected when the dialog opened: where
    /// "this certificate" goes back to after looking at the whole chain.
    pub index: usize,
    /// File name being typed.
    pub path: String,
    /// Why the last attempt failed.
    pub error: Option<String>,
}

/// A dialog drawn over the screen.
#[derive(Debug, Clone)]
pub enum Modal {
    /// Key reference.
    Help,
    /// Asks for a keystore password.
    Password(PasswordModal),
    /// Asks where and how to export.
    Export(ExportModal),
    /// Asks whether to replace an existing file.
    ConfirmOverwrite(ExportRequest),
}

impl Modal {
    /// Whether this is the help dialog.
    #[must_use]
    pub fn is_help(&self) -> bool {
        matches!(self, Modal::Help)
    }

    /// Whether the dialog takes typed text, so keys must not reach the keymap.
    #[must_use]
    pub fn takes_text(&self) -> bool {
        !self.is_help()
    }
}

/// What the Home input field asks for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HomeMode {
    /// A target to inspect.
    #[default]
    Target,
    /// The path of a file listing the targets of a batch.
    BatchFile,
}

/// State of the Home screen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HomeState {
    /// What `input` is being typed for.
    pub mode: HomeMode,
    /// Text typed so far.
    pub input: String,
    /// Cursor position inside `input`, in characters.
    pub cursor: usize,
    /// Whether keys type into `input` instead of acting as commands.
    pub editing: bool,
    /// Recent targets, newest first (a view of the history).
    pub recents: Vec<String>,
    /// Favorite targets (a view of the history).
    pub favorites: Vec<String>,
    /// Known targets that start with what is typed (Tab completes the first).
    pub suggestions: Vec<String>,
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
    /// What the job inspects (kept to retry with a password).
    pub target: Target,
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
    /// Whether the screen was opened from a row of the Batch screen, which
    /// is where `Esc` goes back to.
    pub from_batch: bool,
}

impl InspectState {
    /// A screen waiting for job `job`.
    #[must_use]
    pub fn loading(job: JobId, target: Target) -> Self {
        Self {
            job,
            target,
            phase: Phase::Loading,
            selected_cert: 0,
            tab: Tab::default(),
            pane: Pane::default(),
            row_cursor: 0,
            scroll: 0,
            from_batch: false,
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

/// The column a batch table is ordered by.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SortKey {
    /// The order of the list (the default).
    #[default]
    Input,
    /// Days until the leaf expires.
    Days,
    /// Worst outcome.
    Status,
    /// Target name.
    Target,
    /// Subject common name.
    Cn,
    /// Issuer common name.
    Issuer,
    /// Number of errors, then warnings.
    Errors,
}

impl SortKey {
    /// The column after this one, wrapping around to the input order.
    #[must_use]
    pub fn next(self) -> SortKey {
        match self {
            SortKey::Input => SortKey::Days,
            SortKey::Days => SortKey::Status,
            SortKey::Status => SortKey::Target,
            SortKey::Target => SortKey::Cn,
            SortKey::Cn => SortKey::Issuer,
            SortKey::Issuer => SortKey::Errors,
            SortKey::Errors => SortKey::Input,
        }
    }

    /// Name shown in the status line.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            SortKey::Input => "list order",
            SortKey::Days => "days",
            SortKey::Status => "status",
            SortKey::Target => "target",
            SortKey::Cn => "CN",
            SortKey::Issuer => "issuer",
            SortKey::Errors => "errors",
        }
    }
}

/// Where a batch job stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchPhase {
    /// Targets are still being inspected.
    Running,
    /// Every target was inspected.
    Done,
    /// The user stopped it; the rows collected so far stay.
    Cancelled,
}

/// State of the Batch screen.
///
/// Only [`BatchRow`]s are kept, never reports: memory grows with the number
/// of targets and not with the size of their chains. Sorting and filtering
/// work on `view`, a list of indices, so no row is ever cloned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchState {
    /// Job that feeds this screen; events of other jobs are ignored.
    pub job: JobId,
    /// The targets, in list order; a row opens an inspect of its target.
    pub targets: Vec<NetworkTarget>,
    /// The row of each target, in list order, once it arrived.
    pub rows: Vec<Option<BatchRow>>,
    /// Indices into `rows` of the rows shown, in display order.
    pub view: Vec<usize>,
    /// Targets finished so far.
    pub done: usize,
    /// Column the table is ordered by.
    pub sort: SortKey,
    /// Whether the order is reversed.
    pub descending: bool,
    /// Text rows must contain (target, CN or issuer), ignoring case.
    pub filter: String,
    /// Whether keys type into `filter`.
    pub filter_editing: bool,
    /// Position of the selected row in `view`.
    pub selected: usize,
    /// First visible row of `view`.
    pub scroll: usize,
    /// Where the job stands.
    pub phase: BatchPhase,
}

impl BatchState {
    /// A screen waiting for job `job` to inspect `targets`.
    #[must_use]
    pub fn new(job: JobId, targets: Vec<NetworkTarget>) -> Self {
        let total = targets.len();
        Self {
            job,
            targets,
            rows: vec![None; total],
            view: Vec::new(),
            done: 0,
            sort: SortKey::default(),
            descending: false,
            filter: String::new(),
            filter_editing: false,
            selected: 0,
            scroll: 0,
            phase: BatchPhase::Running,
        }
    }

    /// Whether the job is still running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.phase == BatchPhase::Running
    }

    /// Targets in the batch.
    #[must_use]
    pub fn total(&self) -> usize {
        self.targets.len()
    }

    /// The row at position `position` of the table, with its index in the
    /// list.
    #[must_use]
    pub fn row_at(&self, position: usize) -> Option<(usize, &BatchRow)> {
        let index = *self.view.get(position)?;
        self.rows.get(index)?.as_ref().map(|row| (index, row))
    }

    /// The rows of the table, in display order.
    pub fn visible_rows(&self) -> impl Iterator<Item = &BatchRow> {
        self.view
            .iter()
            .filter_map(|index| self.rows.get(*index).and_then(Option::as_ref))
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

/// Reads the list of targets of a batch from the file at the given path, or
/// says why it cannot.
///
/// Injected so `update` stays free of file system access.
pub type BatchLoader = fn(&str) -> Result<Vec<NetworkTarget>, String>;

/// Everything the views draw and `update` changes.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Current screen.
    pub screen: Screen,
    /// Home screen data.
    pub home: HomeState,
    /// Inspect screen data, when a target was opened.
    pub inspect: Option<InspectState>,
    /// Batch screen data, when a batch was started.
    pub batch: Option<BatchState>,
    /// Dialog over the screen.
    pub modal: Option<Modal>,
    /// The export in flight, kept to ask for confirmation or to retry.
    pub pending_export: Option<ExportRequest>,
    /// First visible line of the help dialog.
    pub help_scroll: u16,
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
    /// How the path typed for a batch becomes its targets.
    pub batch_loader: BatchLoader,
    /// Largest text a copy may put on the clipboard, in bytes.
    pub max_clipboard_bytes: usize,
    /// Recent targets and favorites.
    pub history: History,
    /// Most recent targets the history keeps.
    pub history_max_entries: usize,
    /// The wall clock, injected so `update` stays deterministic.
    pub wall_clock: WallClock,
}

/// Reads the wall clock for the history's timestamps.
pub type WallClock = fn() -> Timestamp;

/// Clock used when none is injected: the epoch.
fn epoch() -> Timestamp {
    Timestamp::from_unix_saturating(0)
}

impl AppState {
    /// Refreshes the Home lists from the history, keeping the selection in
    /// range.
    pub fn sync_history_lists(&mut self) {
        self.home.recents = self
            .history
            .recents
            .iter()
            .map(|entry| entry.target.clone())
            .collect();
        self.home.favorites = self.history.favorites.clone();
        let rows = self.home.recents.len() + self.home.favorites.len();
        self.home.selected = self.home.selected.filter(|&i| i < rows);
    }

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
            batch: None,
            modal: None,
            pending_export: None,
            help_scroll: 0,
            toast: None,
            jobs: JobTracker::default(),
            theme: ThemeKind::default(),
            fingerprint_format: FingerprintFormat::default(),
            size: (80, 24),
            now,
            should_quit: false,
            target_parser: crate::update_home::default_target_parser,
            batch_loader: crate::update_home::default_batch_loader,
            max_clipboard_bytes: Limits::default().max_clipboard_bytes,
            history: History::default(),
            history_max_entries: Limits::default().history_entries,
            wall_clock: epoch,
        }
    }
}
