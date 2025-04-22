mod common;
mod entities;

use clap::Parser;
use common::{_generate_sboms, OutputSBOMs, PurlType};
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::{env, fs};

const BOMULATOR_NAME: &str = env!("CARGO_PKG_NAME");
const BOMULATOR_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug, Clone)]
#[command(version, about, arg_required_else_help(true))]
struct Args {
    /// Path to the all.zip file available for download at https://storage.googleapis.com/osv-vulnerabilities/index.html
    #[arg(short, long)]
    input: String,

    /// Path to store the output files. The default is the folder where the tool is executed from
    #[arg(short, long, default_value = "")]
    output_folder: String,

    /// Optional comma-separated list of the PURL types that the selected packages must belong to.
    /// If not provided, all the PURL types will be used.
    #[arg(short = 't', long, value_delimiter = ',', value_enum)]
    purl_types: Vec<PurlType>,

    /// Total number of vulnerabilities requested in the generated SBOM
    #[arg(short = 'v', long, default_value_t = 100)]
    total_vulnerabilities: usize,

    /// Total number of vulnerabilities requested in the generated SBOM
    #[arg(hide = true, long, default_value_t = false)]
    generate_purl_types: bool,
}

// const PROGRESS_BAR_TEMPLATE: &str = "{elapsed} {wide_bar} {pos}/{len} ETA:{eta}";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let OutputSBOMs {
        uuid,
        cyclonedx,
        spdx,
        missing_vulnerabilities,
    } = _generate_sboms(
        args.input,
        args.purl_types,
        args.total_vulnerabilities,
        args.generate_purl_types,
    )
    .await?;

    let base_output_file_path: PathBuf = [
        args.output_folder,
        format!("{}-{}-{}", BOMULATOR_NAME, BOMULATOR_VERSION, uuid),
    ]
    .iter()
    .collect();

    let mut spdx_output_file_path = base_output_file_path.clone();
    spdx_output_file_path = append_ext("spdx.json", spdx_output_file_path);
    fs::write(spdx_output_file_path.as_path(), spdx).unwrap_or_else(|_| {
        panic!(
            "Failed to create SPDX SBOM file {:?}",
            spdx_output_file_path
        )
    });

    let mut cdx_output_file_path = base_output_file_path.clone();
    cdx_output_file_path = append_ext("cdx.json", cdx_output_file_path);
    fs::write(cdx_output_file_path.as_path(), cyclonedx).unwrap_or_else(|_| {
        panic!(
            "Failed to create CycloneDX SBOM file {:?}",
            cdx_output_file_path
        )
    });

    if missing_vulnerabilities > 0 {
        println!(
            "WARN: It has NOT been possible to create SBOMs with {} vulnerabilities as requested but with {} vulnerabilities",
            args.total_vulnerabilities,
            args.total_vulnerabilities as i64 - missing_vulnerabilities
        );
    }
    println!("Created files:");
    println!("{}", cdx_output_file_path.as_path().display());
    println!("{}", spdx_output_file_path.as_path().display());
    Ok(())
}

/// Returns a path with a new dotted extension component appended to the end.
/// Note: does not check if the path is a file or directory; you should do that.
/// # Example
/// ```
/// use pathext::append_ext;
/// use std::path::PathBuf;
/// let path = PathBuf::from("foo/bar/baz.txt");
/// if !path.is_dir() {
///    assert_eq!(append_ext("app", path), PathBuf::from("foo/bar/baz.txt.app"));
/// }
/// ```
/// from https://internals.rust-lang.org/t/pathbuf-has-set-extension-but-no-add-extension-cannot-cleanly-turn-tar-to-tar-gz/14187
///
pub fn append_ext(ext: impl AsRef<OsStr>, path: PathBuf) -> PathBuf {
    let mut os_string: OsString = path.into();
    os_string.push(".");
    os_string.push(ext.as_ref());
    os_string.into()
}
