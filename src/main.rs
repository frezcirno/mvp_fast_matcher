#![allow(non_snake_case)]

use futures::future;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FuncSig {
    path: String,
    signature: String,
    syn_sigs: HashSet<String>,
    sem_sigs: HashSet<(String, String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChangedFuncSig {
    src_func_path: String,
    dst_func_path: String,
    src_func_signature: String,
    dst_func_signature: String,
    S_del: HashSet<String>,
    V_syn: HashSet<String>,
    V_sem: HashSet<(String, String, String)>,
    P_syn: HashSet<String>,
    P_sem: HashSet<(String, String, String)>,
    del_stmts: HashSet<String>,
    add_stmts: HashSet<String>,
    abs_norm_map: HashMap<String, Vec<String>>,
    hash_map: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VulSig {
    vul_id: String,
    commit_id: String,
    func_sigs: Vec<ChangedFuncSig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MatchResult {
    test_vul_id: String,
    test_commit_id: String,
    test_func_sig: FuncSig,
    train_vul_id: String,
    train_commit_id: String,
    train_func_sig: ChangedFuncSig,
}

async fn load_vul_sigs(sig_dir: &PathBuf) -> Vec<VulSig> {
    let mut files = fs::read_dir(sig_dir).await.unwrap();
    let mut futs = Vec::new();
    while let Some(file) = files.next_entry().await.unwrap() {
        let path = file.path();
        // println!("Loading {:?}", path);
        let fut = async move {
            let filestr = fs::read_to_string(path).await.unwrap();
            let mut vul_sig: Vec<VulSig> = serde_json::from_str(&filestr).unwrap();
            assert!(vul_sig.len() == 1);
            vul_sig.pop().unwrap()
        };
        futs.push(fut);
    }

    future::join_all(futs).await
}

async fn load_func_sigs(path: &PathBuf) -> Vec<FuncSig> {
    // read line by line
    let filestr = tokio::fs::read_to_string(path).await.unwrap();
    let lines = filestr.lines().collect::<Vec<&str>>();

    let handles = lines
        .iter()
        .map(|line| async move { serde_json::from_str::<FuncSig>(line).unwrap() });

    future::join_all(handles).await
}

fn ioa<T>(vp: &HashSet<T>, f: &HashSet<T>) -> f32
where
    T: Eq,
    T: Hash,
{
    return vp.intersection(f).count() as f32 / vp.len() as f32;
}

fn match_function(
    f_syn: &HashSet<String>,
    f_sem: &HashSet<(String, String, String)>,
    S_del: &HashSet<String>,
    V_syn: &HashSet<String>,
    V_sem: &HashSet<(String, String, String)>,
    P_syn: &HashSet<String>,
    P_sem: &HashSet<(String, String, String)>,
    t1: f32,
    t2: f32,
    t3: f32,
    t4: f32,
) -> bool {
    // Sanity check
    if V_syn.is_empty() || V_sem.is_empty() {
        return false;
    }

    // C1: S_del ⊆ f_syn
    if !S_del.is_subset(f_syn) {
        return false;
    }

    // C2: V_syn ∩ f_syn
    if ioa(V_syn, f_syn) <= t1 {
        return false;
    }

    // C3: P_syn ∩ f_syn
    if !P_syn.is_empty() && ioa(P_syn, f_syn) > t2 {
        return false;
    }

    // C4: V_sem ∩ f_sem
    if ioa(V_sem, f_sem) <= t3 {
        return false;
    }

    // C5: P_sem ∩ f_sem
    if !P_sem.is_empty() && ioa(P_sem, f_sem) > t4 {
        return false;
    }

    true
}

fn match_vul_signatures(
    func_sig: &FuncSig,
    vul_sig: &ChangedFuncSig,
    t1: f32,
    t2: f32,
    t3: f32,
    t4: f32,
) -> bool {
    match_function(
        &func_sig.syn_sigs,
        &func_sig.sem_sigs,
        &vul_sig.S_del,
        &vul_sig.V_syn,
        &vul_sig.V_sem,
        &vul_sig.P_syn,
        &vul_sig.P_sem,
        t1,
        t2,
        t3,
        t4,
    )
}

async fn mvp_match(
    func_sigs: &[FuncSig],
    vul_sigs: &[VulSig],
    t1: f32,
    t2: f32,
    t3: f32,
    t4: f32,
) -> Vec<MatchResult> {
    let mut hds = vec![];
    for vul_sig in vul_sigs {
        unsafe {
            let vul_sig = std::mem::transmute::<&VulSig, &'static VulSig>(vul_sig);
            let func_sigs = std::mem::transmute::<&[FuncSig], &'static [FuncSig]>(func_sigs);

            let hd: tokio::task::JoinHandle<Vec<MatchResult>> = tokio::spawn(async move {
                // one vul_sig: maybe multiple files
                let mut match_result = Vec::new();
                for vul_func_sig in &vul_sig.func_sigs {
                    for func_sig in func_sigs {
                        if match_vul_signatures(func_sig, vul_func_sig, t1, t2, t3, t4) {
                            let r = MatchResult {
                                test_vul_id: String::from("target"),
                                test_commit_id: String::from("target"),
                                test_func_sig: func_sig.clone(),
                                train_vul_id: vul_sig.vul_id.clone(),
                                train_commit_id: vul_sig.commit_id.clone(),
                                train_func_sig: vul_func_sig.clone(),
                            };
                            match_result.push(r);
                        }
                    }
                }
                match_result
            });
            hds.push(hd);
        }
    }

    let mut all_match_results = vec![];
    for fut in hds {
        let match_result = fut.await.unwrap();
        all_match_results.extend(match_result);
    }
    all_match_results
}

async fn write_results(match_results: &[MatchResult], path: &str) {
    let mut file = fs::File::create(path).await.unwrap();
    for m in match_results {
        let m = serde_json::to_string(&m).unwrap();
        file.write_all(m.as_bytes()).await.unwrap();
        file.write_all(b"\n").await.unwrap();
    }
}

fn read_csv(path: &str) -> Vec<HashMap<String, String>> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_path(path)
        .unwrap();
    let mut res = Vec::new();
    for result in rdr.deserialize() {
        let record: HashMap<String, String> = result.unwrap();
        res.push(record);
    }
    res
}

#[tokio::main(flavor = "multi_thread", worker_threads = 30)]
async fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() != 7 {
        println!(
            "Usage: {} <project-list.csv> <output-dir> <t1=0.8> <t2=0.2> <t3=0.8> <t4=0.2>",
            argv[0]
        );
        std::process::exit(1);
    }

    let project_list = read_csv(&argv[1]);
    let output_dir = PathBuf::from(&argv[2]);
    let t1: f32 = argv[3].parse().unwrap();
    let t2: f32 = argv[4].parse().unwrap();
    let t3: f32 = argv[5].parse().unwrap();
    let t4: f32 = argv[6].parse().unwrap();

    for record in project_list {
        let target = record.get("target").unwrap();
        let version = record.get("version").unwrap();
        let patch_sig_dir = record.get("patch_sig_dir").unwrap();
        let project_sig_dir = record.get("project_sig_dir").unwrap();

        let base_name = format!("{}_{}", target, version.replace('/', "_"));

        let res = output_dir.join(format!("mvp_{}.jsonl", base_name));
        if res.exists() {
            println!("Skip {} {}", target, version);
            continue;
        }

        let project_sig_dir = PathBuf::from(project_sig_dir);
        let project_sigs = project_sig_dir.join(format!(
            "{}_{}_func_sigs.jsonl",
            target,
            version.replace('/', "_")
        ));
        if !project_sigs.exists() {
            continue;
        }

        println!("Processing {} {} {}", target, version, patch_sig_dir);

        let patch_sig_dir = PathBuf::from(patch_sig_dir);
        let vul_sigs = load_vul_sigs(&patch_sig_dir).await;
        println!("Total vul sigs: {}", vul_sigs.len());

        let func_sigs = load_func_sigs(&project_sigs).await;
        println!("Total func sigs: {}", func_sigs.len());

        let matches = mvp_match(&func_sigs, &vul_sigs, t1, t2, t3, t4).await;
        println!("Total matches: {}", matches.len());

        write_results(&matches, res.to_str().unwrap()).await;
    }
}
