#![allow(clippy::unwrap_used)]

//! BDD tests covering StatusCounts and SeverityCounts increment arms.

use evidencebus_codes::{FindingSeverity, PacketStatus};
use evidencebus_types::{SeverityCounts, StatusCounts};

#[test]
fn bdd_given_new_status_counts_when_increment_pass_then_pass_field_grows() {
    let mut counts = StatusCounts::new();
    counts.increment(PacketStatus::Pass);
    assert_eq!(counts.pass, 1);
    assert_eq!(counts.total(), 1);
}

#[test]
fn bdd_given_new_status_counts_when_increment_fail_then_fail_field_grows() {
    let mut counts = StatusCounts::new();
    counts.increment(PacketStatus::Fail);
    assert_eq!(counts.fail, 1);
    assert_eq!(counts.total(), 1);
}

#[test]
fn bdd_given_new_status_counts_when_increment_warn_then_warn_field_grows() {
    let mut counts = StatusCounts::new();
    counts.increment(PacketStatus::Warn);
    assert_eq!(counts.warn, 1);
    assert_eq!(counts.total(), 1);
}

#[test]
fn bdd_given_new_status_counts_when_increment_indeterminate_then_field_grows() {
    let mut counts = StatusCounts::new();
    counts.increment(PacketStatus::Indeterminate);
    assert_eq!(counts.indeterminate, 1);
    assert_eq!(counts.total(), 1);
}

#[test]
fn bdd_given_new_status_counts_when_increment_error_then_error_field_grows() {
    let mut counts = StatusCounts::new();
    counts.increment(PacketStatus::Error);
    assert_eq!(counts.error, 1);
    assert_eq!(counts.total(), 1);
}

#[test]
fn bdd_given_all_status_variants_when_each_incremented_then_total_is_sum() {
    let mut counts = StatusCounts::new();
    counts.increment(PacketStatus::Pass);
    counts.increment(PacketStatus::Fail);
    counts.increment(PacketStatus::Warn);
    counts.increment(PacketStatus::Indeterminate);
    counts.increment(PacketStatus::Error);
    assert_eq!(counts.pass, 1);
    assert_eq!(counts.fail, 1);
    assert_eq!(counts.warn, 1);
    assert_eq!(counts.indeterminate, 1);
    assert_eq!(counts.error, 1);
    assert_eq!(counts.total(), 5);
}

#[test]
fn bdd_given_new_severity_counts_when_increment_note_then_note_field_grows() {
    let mut counts = SeverityCounts::new();
    counts.increment(FindingSeverity::Note);
    assert_eq!(counts.note, 1);
    assert_eq!(counts.total(), 1);
}

#[test]
fn bdd_given_new_severity_counts_when_increment_warning_then_warning_field_grows() {
    let mut counts = SeverityCounts::new();
    counts.increment(FindingSeverity::Warning);
    assert_eq!(counts.warning, 1);
    assert_eq!(counts.total(), 1);
}

#[test]
fn bdd_given_new_severity_counts_when_increment_error_then_error_field_grows() {
    let mut counts = SeverityCounts::new();
    counts.increment(FindingSeverity::Error);
    assert_eq!(counts.error, 1);
    assert_eq!(counts.total(), 1);
}

#[test]
fn bdd_given_all_severity_variants_when_each_incremented_then_total_is_sum() {
    let mut counts = SeverityCounts::new();
    counts.increment(FindingSeverity::Note);
    counts.increment(FindingSeverity::Warning);
    counts.increment(FindingSeverity::Error);
    assert_eq!(counts.note, 1);
    assert_eq!(counts.warning, 1);
    assert_eq!(counts.error, 1);
    assert_eq!(counts.total(), 3);
}
