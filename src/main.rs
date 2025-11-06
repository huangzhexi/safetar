//! Command-line entry point for the safetar binary.

use clap::Parser;

use safetar::error::UserInputError;
use safetar::manifest::ManifestError;
use safetar::policy::PolicyError;

fn main() {
    let cli = safetar::cli::Cli::parse();

    if let Err(err) = safetar::run(cli) {
        let mut exit_code = 1;
        for cause in err.chain() {
            if cause.is::<PolicyError>() || cause.is::<ManifestError>() {
                exit_code = 3;
                break;
            }
            if cause.is::<UserInputError>() {
                exit_code = 2;
                break;
            }
            if cause.is::<std::io::Error>() {
                exit_code = 1;
            }
        }
        eprintln!("safetar: {err:#}");
        std::process::exit(exit_code);
    }
}
