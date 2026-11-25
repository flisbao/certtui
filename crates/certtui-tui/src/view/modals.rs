//! The dialogs that take text: keystore password, export, and the
//! confirmation before replacing a file.

use certtui_app::export::{ExportFormat, ExportSelection};
use certtui_app::present::labels;
use certtui_domain::target::Target;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use crate::app_state::{ExportModal, Modal, PasswordModal};
use crate::msg::ExportRequest;
use crate::theme::Theme;
use crate::update_modal::format_name;

/// Mask drawn for every typed password character.
const MASK: char = '\u{2022}';
/// The text cursor.
const CURSOR: &str = "\u{258f}";
const DIALOG_WIDTH: u16 = 64;

/// Draws `modal` when it is one of the text dialogs.
pub fn render(modal: &Modal, frame: &mut Frame, area: Rect, theme: &Theme) {
    match modal {
        Modal::Help => {}
        Modal::Password(dialog) => password(dialog, frame, area, theme),
        Modal::Export(dialog) => export(dialog, frame, area, theme),
        Modal::ConfirmOverwrite(request) => confirm(request, frame, area, theme),
    }
}

fn target_label(target: &Target) -> String {
    let text = match target {
        Target::Network(network) => format!("{}:{}", network.host, network.port),
        Target::File(path) | Target::Directory { path, .. } => path.to_string_lossy().into_owned(),
        Target::Stdin => "standard input".to_owned(),
    };
    labels::single_line(&text)
}

fn password(dialog: &PasswordModal, frame: &mut Frame, area: Rect, theme: &Theme) {
    let width = usize::from(DIALOG_WIDTH.saturating_sub(6));
    // Never the typed characters, only as many dots as fit.
    let dots: String = std::iter::repeat_n(MASK, dialog.input.len().min(width)).collect();
    let mut lines = vec![
        Line::from(format!("Password for {}", target_label(&dialog.target))),
        Line::from(""),
        Line::from(vec![Span::styled(format!("{dots}{CURSOR}"), theme.base)]),
        Line::from(""),
    ];
    if let Some(error) = &dialog.error {
        lines.push(Line::styled(error.clone(), theme.error));
    }
    lines.push(Line::styled("Enter opens \u{b7} Esc cancels", theme.dim));
    draw(frame, area, theme, " Keystore password ", lines);
}

fn export(dialog: &ExportModal, frame: &mut Frame, area: Rect, theme: &Theme) {
    let format = [ExportFormat::Pem, ExportFormat::Der, ExportFormat::Json]
        .into_iter()
        .map(|candidate| {
            let name = format!(" {} ", format_name(candidate));
            if candidate == dialog.format {
                Span::styled(name, theme.selected)
            } else {
                Span::styled(name, theme.dim)
            }
        })
        .collect::<Vec<_>>();
    let selection = match dialog.selection {
        ExportSelection::Index(index) => format!("certificate #{index}"),
        ExportSelection::Chain => format!(
            "the whole chain ({} certificates)",
            dialog.report.chain.len()
        ),
    };
    let mut lines = vec![
        Line::from([vec![Span::raw("Format  ")], format].concat()),
        Line::from(format!("What    {selection}")),
        Line::from(vec![
            Span::raw("File    "),
            Span::styled(
                format!("{}{CURSOR}", labels::single_line(&dialog.path)),
                theme.base,
            ),
        ]),
        Line::from(""),
    ];
    if let Some(error) = &dialog.error {
        lines.push(Line::styled(error.clone(), theme.error));
    }
    lines.push(Line::styled(
        "Tab format \u{b7} \u{2191}\u{2193} one or all \u{b7} Enter writes \u{b7} Esc cancels",
        theme.dim,
    ));
    draw(frame, area, theme, " Export ", lines);
}

fn confirm(request: &ExportRequest, frame: &mut Frame, area: Rect, theme: &Theme) {
    let path = labels::single_line(&request.path.to_string_lossy());
    let lines = vec![
        Line::from(path),
        Line::from("already exists."),
        Line::from(""),
        Line::styled(
            "Replace it?  y / Enter replaces \u{b7} any other key keeps it",
            theme.warn,
        ),
    ];
    draw(frame, area, theme, " Replace file? ", lines);
}

fn draw(frame: &mut Frame, area: Rect, theme: &Theme, title: &str, lines: Vec<Line<'_>>) {
    let width = area.width.saturating_sub(2).min(DIALOG_WIDTH);
    let height = u16::try_from(lines.len())
        .unwrap_or(u16::MAX)
        .saturating_add(2)
        .min(area.height);
    let rect = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines)
            .style(theme.base)
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme.title)
                    .title(title.to_owned())
                    .title_style(theme.title),
            ),
        rect,
    );
}
