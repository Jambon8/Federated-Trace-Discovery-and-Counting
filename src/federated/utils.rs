use std::collections::HashMap;
use process_mining::dfg::dfg_struct::Activity;
use process_mining::dfg::DirectlyFollowsGraph;
use process_mining::event_log::Trace;
use process_mining::EventLog;
use sha2::{Digest, Sha256};
use std::convert::TryInto;

pub fn recalculate_activity_counts(dfg: &mut DirectlyFollowsGraph) {
    let mut updated_activities: HashMap<Activity, u32> = HashMap::with_capacity(dfg.activities.len());

    dfg.activities.iter().for_each(|(act, _)| {
        let mut new_count: u32;

        new_count = dfg
            .get_ingoing_df_relations(act)
            .iter()
            .map(|dfr| dfg.directly_follows_relations.get(dfr).unwrap())
            .sum();
        new_count = new_count.max(
            dfg.get_outgoing_df_relations(act)
                .iter()
                .map(|dfr| dfg.directly_follows_relations.get(dfr).unwrap())
                .sum(),
        );

        updated_activities.insert(act.clone(), new_count);
    });

    dfg.activities = updated_activities;
}

///
/// Computes a dictionary from a trace's name to the trace for all traces in the event log
///
pub fn find_name_trace_dictionary(event_log: &EventLog) -> HashMap<&String, &Trace> {
    let mut result: HashMap<&String, &Trace> = HashMap::new();

    event_log.traces.iter().for_each(|t| {
        result.insert(
            event_log.get_trace_attribute(t, "concept:name")
                .unwrap()
                .value
                .try_as_string()
                .unwrap(),
            t,
        );
    });

    result
}

/// Hashes a string using Sha256 and returns the first 8 bytes as a u64.
/// This is a deterministic and consistent way to hash case IDs.
pub fn hash_case_id_to_u64(case_id: &str) -> u64 {
    // Create a new Sha256 hasher
    let mut hasher = Sha256::new();
    // Write the string bytes to the hasher
    hasher.update(case_id.as_bytes());
    // Finalize the hash, returning a 32-byte array
    let result = hasher.finalize();

    // Take the first 8 bytes of the hash and convert them to a u64 number
    u64::from_le_bytes(result[0..8].try_into().expect("Slice with incorrect length"))
}