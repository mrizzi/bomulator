mod common;
mod entities;

use common::_generate_sboms;
pub use common::OutputSBOMs;
pub use common::PurlType;
use std::error::Error;

pub async fn generate_sboms(
    input: String,
    purl_types: Vec<PurlType>,
    total_vulnerabilities: usize,
) -> Result<OutputSBOMs, Box<dyn Error>> {
    _generate_sboms(input, purl_types, total_vulnerabilities, false).await
}
