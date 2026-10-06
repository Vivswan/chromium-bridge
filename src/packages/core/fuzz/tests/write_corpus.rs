//! `write_corpus` into a directory that holds nothing yet, the shape of a fresh checkout: every file
//! under `seeds/` and `dictionaries/` is generated and gitignored, so the nightly job's first step
//! runs where neither directory exists. The incident: once the last tracked file left `dictionaries/`,
//! that step died with "could not write the seed corpus under .../fuzz: No such file or directory".

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use chromium_bridge_fuzz::seeds::{
    corpus, json_dictionary, render_dictionary, write_corpus, Expect, Summary, Written,
    JSON_DICTIONARY,
};

fn files_under(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .components()
                .map(|c| c.as_os_str().to_str().unwrap().to_string())
                .collect::<Vec<_>>()
                .join("/");
            out.insert(relative, fs::read(&path).unwrap());
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

#[test]
fn an_empty_directory_receives_every_seed_and_the_dictionary() {
    let fuzz_dir = tempfile::tempdir().unwrap();
    let summary = write_corpus(fuzz_dir.path())
        .expect("a directory with no seeds/ and no dictionaries/ is where the nightly job starts");

    let corpus = corpus();
    let words = json_dictionary(&corpus);
    let mut expected_files: BTreeMap<String, Vec<u8>> = corpus
        .iter()
        .flat_map(|dir| {
            dir.seeds.iter().map(move |seed| {
                (
                    format!("seeds/{}/{}", dir.target.name, seed.name),
                    seed.bytes.clone(),
                )
            })
        })
        .collect();
    expected_files.insert(
        JSON_DICTIONARY.to_string(),
        render_dictionary(&words).into_bytes(),
    );
    let expected_summary = Summary {
        directories: corpus
            .iter()
            .map(|dir| Written {
                target: dir.target.name,
                accepted: dir
                    .seeds
                    .iter()
                    .filter(|seed| matches!(seed.expect, Expect::Accepted(_)))
                    .count(),
                refused: dir
                    .seeds
                    .iter()
                    .filter(|seed| matches!(seed.expect, Expect::Refused(_)))
                    .count(),
            })
            .collect(),
        dictionary_words: words.len(),
    };

    assert_eq!(
        files_under(fuzz_dir.path()),
        expected_files,
        "the directory holds every seed and the dictionary, byte for byte, and nothing else"
    );
    assert_eq!(
        summary, expected_summary,
        "the summary counts what was written"
    );
}
