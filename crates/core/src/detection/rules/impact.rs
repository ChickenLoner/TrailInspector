use std::sync::Arc;
use crate::store::Store;
use crate::detection::Finding;
use super::window::{identity_burst, window_burst, Burst, Windows};

/// Shared body of IM-04/05/06: one EC2 operation, >`threshold` by a single
/// identity inside `window_ms`.
fn mass_ec2_op(store: &Store, event_name: &str, threshold: usize, window_ms: i64) -> Burst {
    let ids = match store.idx_event_name.get(event_name) {
        Some(ids) => ids,
        None => return Burst { ids: vec![], keys: vec![] },
    };
    identity_burst(store, ids, threshold + 1, window_ms, Windows::First)
}

/// IM-01: EC2 Instances Launched in Bulk (>5 RunInstances in 10 min, any identity)
pub fn im_01_ec2_bulk_launch(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("RunInstances")?;

    let threshold = 5;
    // Account-wide, not per-identity: everything lands in one group. Every
    // qualifying window counts, since the finding is the overall launch volume
    // rather than one principal crossing a line.
    let one_group: Arc<str> = Arc::from("");
    let burst = window_burst(
        store,
        ids,
        |_| Arc::clone(&one_group),
        threshold + 1,
        10 * 60 * 1000,
        Windows::All,
    );

    if burst.is_empty() {
        return None;
    }

    Some(
        Finding::new(
            format!(
                ">{threshold} EC2 RunInstances events within 10 minutes. \
                 Bulk launches may indicate cryptomining or resource abuse."
            ),
            burst.ids,
            "eventName=RunInstances",
        )
        .meta("total_run_instances", ids.len().to_string()),
    )
}

/// IM-02: Resource Deletion Spree (>10 Delete*/Terminate* events in 5 min by same identity)
pub fn im_02_resource_deletion_spree(store: &Store) -> Option<Finding> {
    // Collect all Delete* and Terminate* events
    let mut deletion_ids: Vec<u32> = vec![];

    for (event_name, ids) in &store.idx_event_name {
        if event_name.starts_with("Delete")
            || event_name.starts_with("Terminate")
            || event_name.starts_with("Destroy")
            || event_name.starts_with("Remove")
        {
            deletion_ids.extend(ids);
        }
    }

    if deletion_ids.is_empty() {
        return None;
    }

    let threshold = 10;
    let burst = identity_burst(store, deletion_ids, threshold + 1, 5 * 60 * 1000, Windows::First);

    if burst.is_empty() {
        return None;
    }

    // Scope to the specific identity if single offender
    let query = if burst.keys.len() == 1 {
        burst.scoped_query("eventName=Delete*")
    } else {
        "eventName=Delete* OR eventName=Terminate*".to_string()
    };

    let identities = burst.keys_joined();
    Some(
        Finding::new(
            format!(
                ">{threshold} Delete/Terminate/Destroy events within 5 minutes by the same identity. \
                 This pattern indicates destructive activity or ransomware. Identities: {identities}"
            ),
            burst.ids,
            query,
        )
        .meta("identities", identities),
    )
}

/// IM-04: Mass EC2 Instance Stop (>3 StopInstances by same identity in 5 min)
pub fn im_04_mass_instance_stop(store: &Store) -> Option<Finding> {
    let threshold = 3;
    let burst = mass_ec2_op(store, "StopInstances", threshold, 5 * 60 * 1000);

    if burst.is_empty() {
        return None;
    }

    let query = burst.scoped_query("eventName=StopInstances");
    let identities = burst.keys_joined();

    Some(
        Finding::new(
            format!(
                ">{threshold} StopInstances events within 5 minutes by the same identity. \
                 Bulk stops are a common ransomware precursor — instances are stopped before \
                 EBS snapshots are exfiltrated or encrypted. Identities: {identities}"
            ),
            burst.ids,
            query,
        )
        .meta("identities", identities),
    )
}

/// IM-05: Mass EC2 Instance Terminate (>3 TerminateInstances by same identity in 5 min)
pub fn im_05_mass_instance_terminate(store: &Store) -> Option<Finding> {
    let threshold = 3;
    let burst = mass_ec2_op(store, "TerminateInstances", threshold, 5 * 60 * 1000);

    if burst.is_empty() {
        return None;
    }

    let query = burst.scoped_query("eventName=TerminateInstances");
    let identities = burst.keys_joined();

    Some(
        Finding::new(
            format!(
                ">{threshold} TerminateInstances events within 5 minutes by the same identity. \
                 Bulk termination is irreversible and indicates destructive wiper or ransomware activity. \
                 Identities: {identities}"
            ),
            burst.ids,
            query,
        )
        .meta("identities", identities),
    )
}

/// IM-06: Mass EC2 Instance Start (>5 StartInstances by same identity in 5 min)
pub fn im_06_mass_instance_start(store: &Store) -> Option<Finding> {
    let threshold = 5;
    let burst = mass_ec2_op(store, "StartInstances", threshold, 5 * 60 * 1000);

    if burst.is_empty() {
        return None;
    }

    let query = burst.scoped_query("eventName=StartInstances");
    let identities = burst.keys_joined();

    Some(
        Finding::new(
            format!(
                ">{threshold} StartInstances events within 5 minutes by the same identity. \
                 Bulk starts on pre-existing stopped instances may indicate unauthorized \
                 compute spin-up for cryptomining. Identities: {identities}"
            ),
            burst.ids,
            query,
        )
        .meta("identities", identities),
    )
}

