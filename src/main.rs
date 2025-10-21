use process_mining::{import_xes_file, XESImportOptions};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Instant;
use tfhe::set_server_key;
use federated_discovery::federated::organization_communication;
use federated_discovery::federated::organization_struct::{
    PrivateKeyOrganization, PublicKeyOrganization,
};

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 6 {
        eprintln!("Usage: {} <log_a> <log_b> <output.json> <debug_mode> <use_psi>", args.get(0).unwrap_or(&"program".to_string()));
        return Ok(());
    }
    
    let path1 = &args[1];
    let path2 = &args[2];
    let output_file = &args[3];
    let debug = args[4].parse::<bool>().expect("Debug flag must be true or false");
    let use_psi = args[5].parse::<bool>().expect("Use_psi flag must be true or false");

    let mut options = XESImportOptions::default();
    options.sort_events_with_timestamp_key = Some("time:timestamp".to_string());
    let mut log1 = import_xes_file(path1, options.clone()).unwrap();
    let mut log2 = import_xes_file(path2, options).unwrap();

    log1.traces.retain(|trace| !trace.events.is_empty());
    log2.traces.retain(|trace| !trace.events.is_empty());

    println!(
        "Start trace variant discovery to be output to {}",
        output_file
    );
    let time_start = Instant::now();

    let mut org_a = PrivateKeyOrganization::new(log1, debug);
    set_server_key(org_a.get_server_key());
    let true_val = org_a.encrypt_true();

    let mut org_b = PublicKeyOrganization::new(log2, true_val);

    // The function now returns a HashMap of trace frequencies
    let trace_frequencies: HashMap<String, usize> =
        organization_communication::communicate(&mut org_a, &mut org_b, 100, use_psi);
    
    let time_elapsed = time_start.elapsed().as_millis();
    println!("Total time elapsed is {}ms", time_elapsed);

    // Write the trace frequencies to a JSON file
    println!("Writing trace frequencies to {}", output_file);
    let file = File::create(output_file)?;
    let mut writer = BufWriter::new(file);
    // Use the `serde_json` crate to serialize the HashMap to a pretty JSON string
    let json = serde_json::to_string_pretty(&trace_frequencies).unwrap();
    writeln!(writer, "{}", json)?;
    writer.flush()?;

    println!("Done.");
    Ok(())
}