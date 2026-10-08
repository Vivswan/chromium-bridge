//! Write the seed corpus and the JSON dictionary into this crate's `seeds/` and `dictionaries/`:
//! `cargo run --manifest-path src/packages/core/fuzz/Cargo.toml --example seeds` (`moon run
//! fuzz-seeds`). Runs before every fuzz pass; the output is gitignored.

use std::path::Path;
use std::process::ExitCode;

use genkan_fuzz::seeds::{write_corpus, JSON_DICTIONARY};

fn main() -> ExitCode {
    let fuzz_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    match write_corpus(fuzz_dir) {
        Ok(summary) => {
            for dir in &summary.directories {
                println!(
                    "seeds/{}: {} seeds ({} accepted, {} adversarial)",
                    dir.target,
                    dir.accepted + dir.refused,
                    dir.accepted,
                    dir.refused
                );
            }
            println!("{JSON_DICTIONARY}: {} words", summary.dictionary_words);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "error: could not write the seed corpus under {}: {e}",
                fuzz_dir.display()
            );
            ExitCode::FAILURE
        }
    }
}
