use assert_cmd::Command;
use assert_cmd::prelude::OutputOkExt;
use itertools::Itertools;
use json_diff_ng::{Mismatch, compare_strs};
use regex::Regex;
use std::fs;
use std::path::Path;

const BOMULATOR_NAME: &str = env!("CARGO_PKG_NAME");

#[test]
fn test_input_non_existent() {
    Command::cargo_bin(BOMULATOR_NAME)
        .unwrap()
        .args(["non-existent"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn test_default_vulnerabilities_default_types() {
    let temp = assert_fs::TempDir::new().unwrap();
    let command_output = Command::cargo_bin(BOMULATOR_NAME)
        .unwrap()
        .arg("-i")
        .arg("./tests/input/2025-04-02_all.zip")
        .arg("-o")
        .arg(temp.path())
        .assert()
        .success()
        .get_output()
        .clone()
        .unwrap();
    let output = String::from_utf8(command_output.stdout).unwrap();
    let output_lines = output.lines().collect_vec();
    // the paths for the created SBOMs must be the last two lines of the stdout
    let cdx_output = output_lines[output_lines.len() - 2];
    let spdx_output = output_lines[output_lines.len() - 1];

    let cdx_output_content = fs::read_to_string(Path::new(cdx_output)).unwrap();
    let cdx_output_content_expected = fs::read_to_string(Path::new(
        "./tests/output_expected/test_default_vulnerabilities_default_types.cdx.json",
    ))
    .unwrap();
    let cdx_diffs = compare_strs_cdx(&cdx_output_content, &cdx_output_content_expected);
    assert!(cdx_diffs.is_empty(), "CycloneDx diffs: {:?}", cdx_diffs);

    let spdx_output_content = fs::read_to_string(Path::new(spdx_output)).unwrap();
    let spdx_output_content_expected = fs::read_to_string(Path::new(
        "./tests/output_expected/test_default_vulnerabilities_default_types.spdx.json",
    ))
    .unwrap();
    let spdx_diffs = compare_strs_spdx(&spdx_output_content, &spdx_output_content_expected);
    assert!(spdx_diffs.is_empty(), "SPDX diffs: {:?}", spdx_diffs);

    temp.close().unwrap();
}

#[test]
fn test_custom_vulnerabilities_custom_types() {
    let temp = assert_fs::TempDir::new().unwrap();
    let command_output = Command::cargo_bin(BOMULATOR_NAME)
        .unwrap()
        .arg("-i")
        .arg("./tests/input/2025-04-02_all.zip")
        .arg("-o")
        .arg(temp.path())
        .arg("-t")
        .arg("maven,cargo")
        .arg("-v")
        .arg("1130")
        .assert()
        .success()
        .get_output()
        .clone()
        .unwrap();
    let output = String::from_utf8(command_output.stdout).unwrap();
    let output_lines = output.lines().collect_vec();
    // the paths for the created SBOMs must be the last two lines of the stdout
    let cdx_output = output_lines[output_lines.len() - 2];
    let spdx_output = output_lines[output_lines.len() - 1];

    let cdx_output_content = fs::read_to_string(Path::new(cdx_output)).unwrap();
    let cdx_output_content_expected = fs::read_to_string(Path::new(
        "./tests/output_expected/test_custom_vulnerabilities_custom_types.cdx.json",
    ))
    .unwrap();
    let cdx_diffs = compare_strs_cdx(&cdx_output_content, &cdx_output_content_expected);
    assert!(cdx_diffs.is_empty(), "CycloneDx diffs: {:?}", cdx_diffs);

    let spdx_output_content = fs::read_to_string(Path::new(spdx_output)).unwrap();
    let spdx_output_content_expected = fs::read_to_string(Path::new(
        "./tests/output_expected/test_custom_vulnerabilities_custom_types.spdx.json",
    ))
    .unwrap();
    let spdx_diffs = compare_strs_spdx(&spdx_output_content, &spdx_output_content_expected);
    assert!(spdx_diffs.is_empty(), "SPDX diffs: {:?}", spdx_diffs);

    temp.close().unwrap();
}

fn compare_strs_cdx(cdx_output_content: &str, cdx_output_content_expected: &str) -> Mismatch {
    compare_strs(
        cdx_output_content,
        cdx_output_content_expected,
        true,
        &[
            Regex::new(r#"serialNumber"#).unwrap(),
            Regex::new(r#"version"#).unwrap(),
        ],
    )
    .unwrap()
}

fn compare_strs_spdx(spdx_output_content: &str, spdx_output_content_expected: &str) -> Mismatch {
    compare_strs(
        spdx_output_content,
        spdx_output_content_expected,
        true,
        &[
            Regex::new(r#"documentNamespace"#).unwrap(),
            Regex::new(r#"creators"#).unwrap(),
            Regex::new(r#"created"#).unwrap(),
        ],
    )
    .unwrap()
}
