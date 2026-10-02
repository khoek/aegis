use crate::ui;

use super::host_list;

pub(super) const CONTACT_TICKS: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub(super) struct HostProgressList {
    group: ui::LiveGroup,
    target: ui::ConfiguredRenderTarget,
}

impl HostProgressList {
    pub(super) fn new(footer_message: impl Into<String>) -> Self {
        Self {
            group: ui::live_group(footer_message)
                .expect("host progress-list footer messages are non-empty"),
            target: ui::render_target(),
        }
    }

    pub(super) fn insert_host(&self, host: &host_list::ListedHost) -> ui::LiveRow {
        self.insert_rendered_host(host_list::render_listed_host(host, &self.target))
    }

    pub(super) fn insert_aligned_host(
        &self,
        host: &host_list::ListedHost,
        layout: &host_list::HostListLayout,
    ) -> ui::LiveRow {
        self.insert_rendered_host(host_list::render_aligned_listed_host(
            host,
            &self.target,
            layout,
        ))
    }

    fn insert_rendered_host(&self, message: String) -> ui::LiveRow {
        self.group
            .rendered_row(message)
            .expect("rendered host rows are non-empty")
    }

    pub(super) fn update_host(&self, row: &ui::LiveRow, host: &host_list::ListedHost) {
        row.set_rendered(host_list::render_listed_host(host, &self.target));
    }

    pub(super) fn update_host_silently(&self, row: &ui::LiveRow, host: &host_list::ListedHost) {
        row.set_detail(host_list::render_listed_host(host, &self.target));
    }

    pub(super) fn update_aligned_host(
        &self,
        row: &ui::LiveRow,
        host: &host_list::ListedHost,
        layout: &host_list::HostListLayout,
    ) {
        row.set_rendered(host_list::render_aligned_listed_host(
            host,
            &self.target,
            layout,
        ));
    }

    pub(super) fn update_aligned_host_silently(
        &self,
        row: &ui::LiveRow,
        host: &host_list::ListedHost,
        layout: &host_list::HostListLayout,
    ) {
        row.set_detail(host_list::render_aligned_listed_host(
            host,
            &self.target,
            layout,
        ));
    }

    pub(super) fn finish_host(&self, row: &ui::LiveRow, host: &host_list::ListedHost) {
        row.finish_rendered(host_list::render_listed_host(host, &self.target));
    }

    pub(super) fn fail_host(&self, row: &ui::LiveRow, host: &host_list::ListedHost) {
        row.fail(host_list::render_listed_host(host, &self.target));
    }

    pub(super) fn abandon_host(&self, row: &ui::LiveRow, host: &host_list::ListedHost) {
        row.abandon(host_list::render_listed_host(host, &self.target));
    }

    pub(super) fn clear_host(&self, row: &ui::LiveRow) {
        row.clear();
    }

    pub(super) fn set_footer(&self, message: impl Into<String>) {
        self.group.set_summary(message);
    }

    pub(super) fn finish_footer(&self, message: impl Into<String>) {
        self.group.finish(message);
    }

    pub(super) fn fail_footer(&self, message: impl Into<String>) {
        self.group.fail(message);
    }

    pub(super) fn abandon_footer(&self, message: impl Into<String>) {
        self.group.abandon(message);
    }

    pub(super) fn clear_footer(&self) {
        self.group.clear();
    }
}
