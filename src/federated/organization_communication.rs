use crate::federated::organization_struct::{PrivateKeyOrganization, PublicKeyOrganization};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::collections::{HashMap, HashSet};
use tfhe::ServerKey;

/// The protocol for the federated computation of a directly-follows graph between two organizations
///
/// # Arguments
///
/// * `org_a`: A private key-owning organization
/// * `org_b`: A public key-owning organization.
/// * `window_size`: A window size to reduce the number of traces to be computed in B.
///
/// Returns: A map of trace variants to their frequency.
///
pub fn communicate<'a>(
    org_a: &'a mut PrivateKeyOrganization,
    org_b: &'a mut PublicKeyOrganization,
    window_size: usize,
    use_psi: bool,
) -> HashMap<String, usize> { // <-- Return type changed
    let mut case_id_hom_comparisons: u64 = 0;
    let mut case_id_hom_selections: u64 = 0;
    let mut timestamp_hom_comparisons: u64 = 0;
    let mut selection_hom_comparisons: u64 = 0;
    
    println!("Start communication");
    println!("Exchange keys");
    let server_key: ServerKey = org_a.get_server_key();
    org_b.set_server_key(server_key);

    let shared_case_ids: HashSet<String>;
    if use_psi {
        println!("Apply private set intersection");
        let (case_ids, encrypted_case_ids) = org_a.encrypt_all_case_ids();
        let shared_case_id_result =
            org_b.find_shared_case_ids(&encrypted_case_ids, &mut case_id_hom_comparisons, &mut case_id_hom_selections);
        shared_case_ids =
            org_a.decrypt_and_identify_shared_case_ids(&case_ids, &shared_case_id_result);
    } else {
        println!("Apply set intersection");
        let org_a_case_ids = org_a.get_all_case_ids();
        shared_case_ids = org_b
            .get_all_case_ids()
            .intersection(&org_a_case_ids.iter().cloned().collect())
            .cloned()
            .collect();

           println!("DEBUG Federated: Org A has {} cases, Org B has {} cases, Shared cases: {}", 
            org_a_case_ids.len(), org_b.get_all_case_ids().len(), shared_case_ids.len());

    }

    println!("Agree on activity encoding");
    let activities_b = org_b.find_activities();
    let agreed_activity_to_pos = org_a.update_with_foreign_activities(activities_b);

    let mut sample_encryptions = org_a.provide_sample_encryptions();
    org_b.sanitize_sample_encryptions(&mut sample_encryptions);
    org_b.set_activity_to_pos(agreed_activity_to_pos, &sample_encryptions);

    println!("Encrypt & encode data for organization A");
    let org_a_encrypted_data = org_a.encrypt_all_data(&shared_case_ids);

    org_b.set_foreign_case_to_trace(org_a_encrypted_data);
    org_b.compute_all_case_names();

    println!("Encrypt & encode data for organization B");
    org_b.encrypt_all_data(&sample_encryptions);

    let max_size = org_b.get_cases_len();
    let multi_bar = MultiProgress::new();
    let progress_cases = multi_bar.add(ProgressBar::new(max_size as u64));
    progress_cases.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
        )
        .unwrap(),
    );
    
    println!("Computing merged traces for all shared cases...");
    
    // Collect all encrypted traces in batches
    let mut all_encrypted_traces = HashMap::new();
    for step in (0..max_size).step_by(window_size) {
        let upper_bound = (step + window_size).min(max_size);
        let encrypted_traces_batch =
            org_b.find_all_secrets(step, upper_bound, &progress_cases, &mut timestamp_hom_comparisons, &mut selection_hom_comparisons, &org_a);
        all_encrypted_traces.extend(encrypted_traces_batch);
    }
    progress_cases.finish();

    println!("Decrypting traces and computing frequencies...");

    let mut trace_frequencies: HashMap<String, usize> = HashMap::new();
    for (_, encrypted_trace) in all_encrypted_traces {
        // Ask Org A to decrypt the trace
        let decrypted_trace_activities = org_a.decrypt_trace(&encrypted_trace);
        // Create the string representation (e.g., "A -> B -> C")
        let trace_string = decrypted_trace_activities.join(" -> ");
        // Increment the count for this trace variant
        *trace_frequencies.entry(trace_string).or_insert(0) += 1;
    }

    println!("Number of homomorphic timestamp comparions: {}", timestamp_hom_comparisons);
    
    trace_frequencies
}