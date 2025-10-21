use crate::federated::utils;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressFinish, ProgressStyle};
use process_mining::event_log::event_log_struct::EventLogClassifier;
use process_mining::event_log::{Event, Trace, XESEditableAttribute};
use process_mining::EventLog;
use rand::seq::SliceRandom;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::hash::{Hash, Hasher, SipHasher};
use std::ops::Not;
use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ClientKey, Config, ConfigBuilder, FheBool, FheUint16,
    FheUint64, ServerKey,
};

/// Computes the activities present in an event log.
///
/// # Arguments
///
/// * `event_log`: An event log.
///
/// Returns: HashSet<String, RandomState> The set of activities of the event log
///
pub fn find_activities(event_log: &EventLog) -> HashSet<String> {
    let mut result = HashSet::new();
    let classifier = EventLogClassifier::default();

    event_log.traces.iter().for_each(|trace| {
        trace.events.iter().for_each(|event| {
            result.insert(classifier.get_class_identity(event));
        })
    });

    result
}

/// Obtains the timestamp of an event in the right format, i.e., a `u32`.
///
/// # Arguments
///
/// * `event`: An event.
///
/// Returns: u32 The timestamp of the event.
///
pub fn get_timestamp(event: &Event) -> u64 {
     event
    .attributes
    .get_by_key("time:timestamp")
    .and_then(|t| t.value.try_as_date())
    .unwrap()
    .timestamp_millis() as u64
}

///
/// The organization with the private key.
///
pub struct PrivateKeyOrganization {
    private_key: ClientKey,
    server_key: ServerKey,
    event_log: EventLog,
    activity_to_pos: HashMap<String, usize>,
    pos_to_activity: HashMap<usize, String>,
    debug: bool,
}

impl PrivateKeyOrganization {
    /// Decrypts a single FheBool. This simulates the interactive step where
    /// Org A provides its decryption service to Org B for a single bit.
    pub fn decrypt_bool(&self, encrypted_bool: &FheBool) -> bool {
        encrypted_bool.decrypt(&self.private_key)
        //*encrypted_bool
     }
     ///
     /// Initializing function
     ///
     pub fn new(event_log: EventLog, debug: bool) -> Self {
        let config: Config = ConfigBuilder::default().build();
        let (private_key, server_key): (ClientKey, ServerKey) = generate_keys(config);
         Self {
            private_key,
            server_key,
             event_log,
            activity_to_pos: HashMap::new(),
            pos_to_activity: HashMap::new(),
            debug,
         }
     }

    /// Decrypts an entire trace of encrypted activities into a sequence of activity names.
    pub fn decrypt_trace(&self, trace: &Vec<FheUint16>) -> Vec<String> {
         trace
            .iter()
            .map(|encrypted_activity| {
                // Decrypt the Uin16 to get the integer position
                let pos_u16: u16 = encrypted_activity.decrypt(&self.private_key);
                let pos = pos_u16 as usize;
                // Look up the activity name from the position
                 self.pos_to_activity.get(&pos).unwrap().clone()
            })
        .collect()
    }

    ///
    /// Encrypts a timestamp using the private key
    ///
    pub fn encrypt_timestamp(&self, value: u64, private_key: &ClientKey) -> FheUint64 {
        if self.debug {
            FheUint64::encrypt_trivial(value)
        } else {
            FheUint64::encrypt(value, private_key)
       }
     }

    //pub fn encrypt_timestamp(&self, value: u64, private_key: &ClientKey) -> u64 {
   //     value
    //}

    ///
    /// Encrypts an encoded activity using the private key.
    ///
    //pub fn encrypt_activity(&self, value: u16, private_key: &ClientKey) -> u16 {
    //    value
    //}

    pub fn encrypt_activity(&self, value: u16, private_key: &ClientKey) -> FheUint16 {
    if self.debug {
        FheUint16::encrypt_trivial(value)
    } else {
        FheUint16::encrypt(value, private_key)
    }
}

    pub fn encrypt_true(&self) -> FheBool {
        if self.debug {
            FheBool::encrypt_trivial(true)
        } else {
            FheBool::encrypt(true, &self.private_key)
        }
    }

    //pub fn encrypt_true(&self) -> bool { // Changed from FheBool
    //    true
    //}

    ///
    /// Decrypts an encrypted activity using the private key.
    ///
    //fn decrypt_activity(&self, val: u16) -> u16 {
    //    val
    //}
    pub fn decrypt_activity(&self, val: FheUint16) -> u16 {
        val.decrypt(&self.private_key)
    }

    ///
    /// Encrypts all its timestamps and activities of a trace.
    ///
    pub fn encrypt_all_data(
     &self,
         shared_case_ids: &HashSet<String>,
    ) -> HashMap<String, (Vec<FheUint16>, Vec<FheUint64>)> {
         self.compute_case_to_trace_with_encryption(
         &self.activity_to_pos,
            &self.private_key,
         &self.event_log,
         shared_case_ids,
    )
    }

    pub fn get_all_case_ids(&self) -> Vec<String> {
     self.event_log
            .traces
            .iter()
            .map(|trace| {
             self.event_log
            .get_trace_attribute(trace, "concept:name")
            .unwrap()
            .value
            .try_as_string()
            .unwrap()
            .to_string()
                       })
                       .collect()
         }

    pub fn encrypt_all_case_ids(&self) -> (Vec<String>, Vec<FheUint64>) {
              let case_ids = self
                       .event_log
                       .traces
                       .iter()
                       .map(|trace| {
                            self.event_log
            .get_trace_attribute(trace, "concept:name")
            .unwrap()
            .value
            .try_as_string()
            .unwrap()
            .to_string()
                       })
                       .collect::<Vec<_>>();

        println!("Encrypt case IDs for organization A");
              let bar = ProgressBar::new(self.event_log.traces.len() as u64);
              bar.set_style(
                       ProgressStyle::with_template(
                            "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
                       )
                       .unwrap(),
              );

        let encrypted_case_ids = case_ids
                       .par_iter()
                       .progress_with(bar)
                       .with_finish(ProgressFinish::AndLeave)
            .map(|case_id| {
                let mut hasher = SipHasher::new();
                case_id.hash(&mut hasher);
                let hashed_case_id = hasher.finish();

                if !self.debug {
                    FheUint64::encrypt(hashed_case_id, &self.private_key)
                    //hashed_case_id
                } else {
                    FheUint64::encrypt_trivial(hashed_case_id)
                    //hashed_case_id
                }
            })
                       .collect();

        (case_ids, encrypted_case_ids)
         }

         pub fn decrypt_and_identify_shared_case_ids(
              &self,
              own_case_ids: &Vec<String>,
        case_id_check_result: &Vec<(usize, FheBool)>,
         ) -> HashSet<String> {
              case_id_check_result
                       .par_iter()
            .filter_map(|(id, enc_bool)| {
                if FheBool::decrypt(enc_bool, &self.private_key) {
            Some(own_case_ids.get(*id).unwrap().to_string())
                            } else {
            None
                            }
                       })
                       .collect()
         }

         ///
         /// Encodes and "encrypts" a trace's activities and timestamps.
         ///
         pub fn preprocess_trace_private_with_encryption(
              &self,
              activity_to_pos: &HashMap<String, usize>,
        private_key: &ClientKey,
              trace: &Trace,
    ) -> (Vec<FheUint16>, Vec<FheUint64>) {
        let mut activities: Vec<FheUint16> = Vec::with_capacity(trace.events.len());
        let mut timestamps: Vec<FheUint64> = Vec::with_capacity(trace.events.len());

              let classifier = EventLogClassifier::default();

              trace.events.iter().for_each(|event| {
                       let activity: String = classifier.get_class_identity(event);
                       let activity_pos: u16 =
                            u16::try_from(activity_to_pos.get(&activity).unwrap().clone()).unwrap_or(0);
            activities.push(self.encrypt_activity(activity_pos, private_key));
            timestamps.push(self.encrypt_timestamp(get_timestamp(event), private_key));
              });

              (activities, timestamps)
         }

         ///
    /// Computes the encrypted sequences for each trace.
         ///
         pub fn compute_case_to_trace_with_encryption(
              &self,
              activity_to_pos: &HashMap<String, usize>,
        private_key: &ClientKey,
              event_log: &EventLog,
              shared_case_ids: &HashSet<String>,
    ) -> HashMap<String, (Vec<FheUint16>, Vec<FheUint64>)> {
              let name_to_trace: HashMap<&String, &Trace> = utils::find_name_trace_dictionary(event_log);
              let name_to_trace_vec: Vec<(&String, &Trace)> = name_to_trace
                       .iter()
                       .filter_map(|(&k, &v)| {
                            if shared_case_ids.contains(&k.to_string()) {
            Some((k, v))
                            } else {
            None
                            }
                       })
                       .collect();

              let bar = ProgressBar::new(name_to_trace.len() as u64);
              bar.set_style(
                       ProgressStyle::with_template(
                            "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
                       )
                       .unwrap(),
              );
        bar.println("Encrypt data organization A");
        let result: HashMap<String, (Vec<FheUint16>, Vec<FheUint64>)> = name_to_trace_vec
                       .into_par_iter()
                       .progress_with(bar)
                       .with_finish(ProgressFinish::AndLeave)
                       .map(|(name, trace)| {
                            (
            name.clone(),
            self.preprocess_trace_private_with_encryption(
                     activity_to_pos,
                        private_key,
                     trace,
            ),
                            )
                       })
            .collect::<HashMap<String, (Vec<FheUint16>, Vec<FheUint64>)>>();

              result
         }

         ///
    /// Sample encrypt all activities with their encoded positions.
    /// B can use the sample encryptions to reduce runtime in terms of encryption.
         ///
    pub fn provide_sample_encryptions(&self) -> HashMap<u16, FheUint16> {
              self.pos_to_activity
                       .par_iter()
                       .map(|(pos, _)| {
                            let pos_u16 = u16::try_from(*pos).unwrap();
                (pos_u16, self.encrypt_activity(pos_u16, &self.private_key))
                       })
            .collect::<HashMap<u16, FheUint16>>()
         }

    ///
    /// Provide the public key that can be used for homomorphic operations.
    ///
    pub fn get_server_key(&self) -> ServerKey {
        self.server_key.clone()
         }

         ///
    /// Creates the encoding using
         ///
         pub fn update_with_foreign_activities(
        // ... (this function remains the same)
              &mut self,
              foreign_activities: HashSet<String>,
         ) -> HashMap<String, usize> {
              let mut activities: HashSet<String> = find_activities(&self.event_log);
              activities.extend(foreign_activities);

              self.activity_to_pos.insert("start".to_string(), 0);
              self.activity_to_pos.insert("end".to_string(), 1);

              activities.iter().enumerate().for_each(|(pos, act)| {
                       self.activity_to_pos.insert(act.clone(), pos + 2);
              });

              self.activity_to_pos.iter().for_each(|(act, pos)| {
                       self.pos_to_activity.insert(*pos, act.clone());
              });

              self.activity_to_pos.clone()
         }

        
}


///
/// Organization B.
///
pub struct PublicKeyOrganization {
         event_log: EventLog,
         activity_to_pos: HashMap<String, usize>,
    own_case_to_trace: HashMap<String, (Vec<FheUint16>, Vec<u64>)>,
    foreign_case_to_trace: HashMap<String, (Vec<FheUint16>, Vec<FheUint64>)>,
    start: Option<FheUint16>,
    end: Option<FheUint16>,
         all_case_names: Vec<String>,
    true_val: FheBool,
}

impl PublicKeyOrganization {
         ///
         /// Initialize function
         ///
    pub fn new(event_log: EventLog, true_val: FheBool) -> Self {
              Self {
                       event_log,
                       own_case_to_trace: HashMap::new(),
                       foreign_case_to_trace: HashMap::new(),
                       activity_to_pos: HashMap::new(),
                       start: None,
                       end: None,
                       all_case_names: Vec::new(),
                       true_val,
              }
         }

         ///
         /// Returns the number of traces
         ///
         pub fn get_cases_len(&self) -> usize {
              self.all_case_names.len()
         }

         ///
    /// Computes the number of encrypted edges to be returned
         ///
         pub fn get_secret_edges_len(&self) -> usize {
              let mut result = 0;
              self.all_case_names.iter().for_each(|case_name| {
                       let (foreign_activities, _) = self
                            .foreign_case_to_trace
                            .get(case_name)
                            .unwrap_or(&(Vec::new(), Vec::new()))
                            .to_owned();

            let (own_activities, _): (Vec<FheUint16>, Vec<u64>) = self
                            .own_case_to_trace
                            .get(case_name)
                            .unwrap_or(&(Vec::new(), Vec::new()))
                            .to_owned();

                       result += foreign_activities.len() + own_activities.len() + 1;
              });
              result
         }

    ///
    /// Sets the public key of the computation that is used for the homomorphic operations
    ///
    pub fn set_server_key(&mut self, server_key: ServerKey) {
        set_server_key(server_key.clone());
        rayon::broadcast(|_| set_server_key(server_key.clone()));
         }

         ///
         /// Computes all activities in the event log
         ///
         pub fn find_activities(&self) -> HashSet<String> {
              find_activities(&self.event_log)
         }

         ///
         /// Sets the dictionary for activity encoding
         ///
         pub fn set_activity_to_pos(
              &mut self,
              activity_to_pos: HashMap<String, usize>,
        sample_encryptions: &HashMap<u16, FheUint16>,
         ) {
              self.activity_to_pos = activity_to_pos;
              self.start = Some(sample_encryptions.get(&(0)).unwrap().clone());
              self.end = Some(sample_encryptions.get(&(1)).unwrap().clone());
         }

         ///
         /// Sanitizes the activities encoded by A
         ///
    pub fn sanitize_sample_encryptions(&self, sample_encryptions: &mut HashMap<u16, FheUint16>) {
              sample_encryptions.iter().for_each(|(val, _)| {
                       if *val >= u16::try_from(sample_encryptions.len()).unwrap_or(0) {
                            panic!()
                       }
              });

        let zero = sample_encryptions.get(&0).unwrap() - sample_encryptions.get(&0).unwrap();

        sample_encryptions
            .par_iter_mut()
            .for_each(|(val, encrypted_val)| {
               *encrypted_val = encrypted_val.eq(*val).select(encrypted_val, &zero);
            })
         }
         

         pub fn find_shared_case_ids(
    &self,
        foreign_case_ids: &Vec<FheUint64>,
    case_id_hom_comparisons: &mut u64,
    case_id_hom_selections: &mut u64,
    ) -> Vec<(usize, FheBool)> {
    let own_case_ids = self
        .event_log
        .traces
        .par_iter()
        .map(|trace| {
                let mut hasher = SipHasher::new();
                self.event_log
                .get_trace_attribute(trace, "concept:name")
                .unwrap()
                .value
                .try_as_string()
                    .unwrap()
                    .hash(&mut hasher);
                hasher.finish()
        })
            .collect::<Vec<_>>();

    println!("Compute case ID intersection at Organization B");
        let bar = ProgressBar::new(self.event_log.traces.len() as u64);
    bar.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
        )
        .unwrap(),
    );

        let partial_result = foreign_case_ids
        .par_iter()
        .enumerate()
        .progress_with(bar)
        .with_finish(ProgressFinish::AndLeave)
        .map(|(pos, case_id)| {
                let mut curr_case_id_hom_comparisons = 0;
                let mut curr_case_id_hom_selections = 0;
                let is_matching: FheBool = self.has_matching_case_id(
                    case_id,
                    &own_case_ids,
                    &mut curr_case_id_hom_comparisons,
                    &mut curr_case_id_hom_selections,
                );
                (
                    pos,
                    is_matching,
                    curr_case_id_hom_comparisons,
                    curr_case_id_hom_selections,
                )
        })
        .collect::<Vec<_>>();

        partial_result
            .iter()
            .for_each(|(_, _, hom_comparisons, hom_selections)| {
                *case_id_hom_comparisons += hom_comparisons;
                *case_id_hom_selections += hom_selections;
            });

        partial_result
            .par_iter()
            .map(|(pos, is_matching, _, _)| (*pos, is_matching.to_owned()))
            .collect::<Vec<_>>()
}

         pub fn get_all_case_ids(&self) -> HashSet<String> {
              self.event_log
                       .traces
                       .iter()
                       .map(|trace| {
                            self.event_log
            .get_trace_attribute(trace, "concept:name")
            .unwrap()
            .value
            .try_as_string()
            .unwrap()
            .to_string()
                       })
                       .collect()
         }

         fn has_matching_case_id(
              &self,
        foreign_case_id: &FheUint64,
              own_case_ids: &Vec<u64>,
              case_id_hom_comparisons: &mut u64,
              case_id_sel_hom_comparisons: &mut u64,
    ) -> FheBool {
              let mut result = FheBool::not(self.true_val.clone());
              *case_id_sel_hom_comparisons += 1;

             own_case_ids.iter().for_each(|&case_id| {
                        result = foreign_case_id.eq(case_id).select(&self.true_val, &result);

                       *case_id_hom_comparisons += 1;
                       *case_id_sel_hom_comparisons += 1;
        });

              result
         }

         ///
    /// Stores and sanitizes the foreign-encrypted data for each case
         ///
         pub fn set_foreign_case_to_trace(
              &mut self,
        mut foreign_case_to_trace: HashMap<String, (Vec<FheUint16>, Vec<FheUint64>)>,
         ) {
        // let max_activities: u16 = u16::try_from(self.activity_to_pos.len() - 1).unwrap_or(0);

        //let len = foreign_case_to_trace.len() as u64;
        //let bar = ProgressBar::new(len);
        // bar.set_style(
        //    ProgressStyle::with_template(
        //        "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
        //    )
      //      .unwrap(),
       //);
       // bar.println("Sanitize activities from A in B");

       // foreign_case_to_trace
        //    .par_iter_mut()
       //     .progress_with(bar)
        //    .with_finish(ProgressFinish::AndLeave)
        //    .for_each(|(_, (foreign_activities, _))| {
        //        foreign_activities.iter_mut().for_each(|act| {
        //            *act = act.max(max_activities);
         //       });
         //   });

              self.foreign_case_to_trace = foreign_case_to_trace;
         }

         ///
         /// Computes all case names present
         ///
         pub fn compute_all_case_names(&mut self) {
               self.all_case_names = self.foreign_case_to_trace.keys().cloned().collect();
               self.all_case_names.shuffle(&mut rand::rng());
         }

         ///
    /// Encrypts all data in organization B
         ///
    pub fn encrypt_all_data(&mut self, sample_encryptions: &HashMap<u16, FheUint16>) {
              self.own_case_to_trace = self.compute_case_to_trace_using_sample_encryption(
                       &self.activity_to_pos,
                       &self.event_log,
                       sample_encryptions,
              );
         }

         pub fn find_all_secrets(
              &self,
              start_case: usize,
              upper_bound: usize,
              bar: &ProgressBar,
              timestamp_hom_comparisons: &mut u64,
              selection_hom_comparisons: &mut u64,
        org_a: &PrivateKeyOrganization,
    ) -> HashMap<String, Vec<FheUint16>> {
              let cases_to_process = self.all_case_names.get(start_case..upper_bound).unwrap();

        // Use Rayon for parallel processing
              let results: Vec<_> = cases_to_process.par_iter().map(|case_name| {
                       let mut local_comps = 0;
        
            // Get the partial traces for the current case
                       let (foreign_activities, foreign_timestamps) = self
                            .foreign_case_to_trace
                            .get(case_name)
                            .map(|(a, t)| (a.as_slice(), t.as_slice()))
                            .unwrap_or((&[], &[]));

                       let (own_activities, own_timestamps) = self
                            .own_case_to_trace
                            .get(case_name)
                            .map(|(a, t)| (a.as_slice(), t.as_slice()))
                            .unwrap_or((&[], &[]));

            // Use the secure merge sort to get the complete encrypted trace
                       let complete_trace = self.secure_merge_traces(
                            foreign_activities,
                            foreign_timestamps,
                            own_activities,
                            own_timestamps,
                            &mut local_comps,
                org_a,
                       );

                       bar.inc(1);
                       (case_name.clone(), complete_trace, local_comps)
              }).collect();

              let mut final_traces = HashMap::new();
              for (name, trace, comps) in results {
                       final_traces.insert(name, trace);
                       *timestamp_hom_comparisons += comps;
              }
        // Note: selection_hom_comparisons is no longer used in this optimized version.
              *selection_hom_comparisons = 0; 

              final_traces
         }

         ///
         /// Encodes the activities using sample encryptions.
         ///
         pub fn preprocess_trace_using_sample_encryption(
              &self,
              activity_to_pos: &HashMap<String, usize>,
              trace: &Trace,
        sample_encryptions: &HashMap<u16, FheUint16>, // debug: bool,
    ) -> (Vec<FheUint16>, Vec<u64>) {
              let classifier = EventLogClassifier::default();

              trace
                       .events
                       .par_iter()
                       .map(|event| {
                            let activity: String = classifier.get_class_identity(event);
                            let activity_pos: u16 =
            u16::try_from(activity_to_pos.get(&activity).unwrap().clone()).unwrap_or(0);
                            (
                    sample_encryptions.get(&activity_pos).unwrap() + 0,
            get_timestamp(event),
                            )
                       })
            .collect::<(Vec<FheUint16>, Vec<u64>)>()
         }

         ///
    /// For each case, it encodes and encrypts the activities
         ///
         pub fn compute_case_to_trace_using_sample_encryption(
              &self,
              activity_to_pos: &HashMap<String, usize>,
              event_log: &EventLog,
        sample_encryptions: &HashMap<u16, FheUint16>,
    ) -> HashMap<String, (Vec<FheUint16>, Vec<u64>)> {
              let name_to_trace: HashMap<&String, &Trace> = utils::find_name_trace_dictionary(event_log);
              let name_to_trace_vec: Vec<(&String, &Trace)> =
                       name_to_trace.iter().map(|(&k, &v)| (k, v)).collect();

              let bar = ProgressBar::new(name_to_trace.len() as u64);
              bar.set_style(
                       ProgressStyle::with_template(
                            "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
                       )
                       .unwrap(),
              );
        bar.println("Encrypt data organization B");

              name_to_trace_vec
                       .into_par_iter()
                       .progress_with(bar)
                       .with_finish(ProgressFinish::AndLeave)
                       .map(|(name, trace)| {
                            (
            name.clone(),
            self.preprocess_trace_using_sample_encryption(
                     activity_to_pos,
                     trace,
                     sample_encryptions,
            ),
                            )
                       })
            .collect::<HashMap<String, (Vec<FheUint16>, Vec<u64>)>>()
         }
    // In src/federated/organization_struct.rs, UPDATE the signature of secure_merge_traces
  
    fn secure_merge_traces(
    &self,
    trace_a: &[FheUint16],
    timestamps_a: &[FheUint64],
    trace_b: &[FheUint16],
    timestamps_b: &[u64],
    timestamp_hom_comparisons: &mut u64,
    org_a: &PrivateKeyOrganization, // Pass in Org A
) -> Vec<FheUint16> {
    if trace_a.is_empty() {
        return trace_b.to_vec();
    }
    if trace_b.is_empty() {
        return trace_a.to_vec();
    }

    let mut complete_trace_activities = Vec::with_capacity(trace_a.len() + trace_b.len());
    let mut ptr_a = 0;
    let mut ptr_b = 0;

    while ptr_a < trace_a.len() && ptr_b < trace_b.len() {
        let timestamp_a = &timestamps_a[ptr_a];
        let timestamp_b = timestamps_b[ptr_b];

        // Securely compare timestamps
        let a_is_earlier_encrypted = timestamp_a.le(timestamp_b);
        *timestamp_hom_comparisons += 1;

        // --- INTERACTIVE STEP ---
        // Org B asks Org A to decrypt the boolean result of the comparison.
        let a_is_earlier_decrypted = org_a.decrypt_bool(&a_is_earlier_encrypted);

        if a_is_earlier_decrypted {
            // If A's event is earlier, push it and advance A's pointer
            complete_trace_activities.push(trace_a[ptr_a].clone());
            ptr_a += 1;
        } else {
            // Otherwise, push B's event and advance B's pointer
            complete_trace_activities.push(trace_b[ptr_b].clone());
            ptr_b += 1;
        }
    }

    // Append any remaining events from the non-exhausted trace
    if ptr_a < trace_a.len() {
        complete_trace_activities.extend_from_slice(&trace_a[ptr_a..]);
    }
    if ptr_b < trace_b.len() {
        complete_trace_activities.extend_from_slice(&trace_b[ptr_b..]);
    }

    complete_trace_activities
    }
}
