use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let input_path = "./tests/input/2025-04-02_all.zip";
    let requested_total_vulnerabilities = 10;
    let bomulator::OutputSBOMs {
        uuid,
        cyclonedx,
        spdx,
        missing_vulnerabilities,
    } = bomulator::generate_sboms(
        input_path.parse().unwrap(),
        vec![],
        requested_total_vulnerabilities,
    )
    .await?;
    println!(
        "The generated SBOMs have UUID {} and they have {} missing vulnerabilities from the requested {} total vulnerabilities",
        uuid, missing_vulnerabilities, requested_total_vulnerabilities
    );
    println!("Generated CycloneDX SBOM\n{}", cyclonedx);
    println!("Generated SPDX SBOM\n{}", spdx);
    Ok(())
}
