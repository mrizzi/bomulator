use crate::entities::osv;
use clap::ValueEnum;
use indicatif::{ProgressBar, ProgressStyle};
use itertools::Itertools;
use packageurl::PackageUrl;
use regex::Regex;
use sea_orm::ActiveValue;
use sea_orm::prelude::Uuid;
use serde::{Deserialize, Serialize};
use serde_cyclonedx::cyclonedx::v_1_6::{
    ComponentBuilder, CycloneDxBuilder, Metadata, MetadataTools, MetadataToolsVariant1, Property,
    Tool,
};
use spdx_rs::models::{
    CreationInfo, DocumentCreationInformation, ExternalPackageReference,
    ExternalPackageReferenceCategory, PackageInformation, PrimaryPackagePurpose, SPDX,
};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::Display;
use std::fs;
use std::io::{Cursor, Read};
use std::str::FromStr;
use std::thread::available_parallelism;
use tokio::task;
use zip::ZipArchive;

const BOMULATOR_NAME: &str = env!("CARGO_PKG_NAME");
const BOMULATOR_VERSION: &str = env!("CARGO_PKG_VERSION");

const PROGRESS_BAR_TEMPLATE: &str = "{elapsed} {wide_bar} {pos}/{len} ETA:{eta}";

#[doc(hidden)]
pub(crate) async fn _generate_sboms(
    input: String,
    purl_types: Vec<PurlType>,
    total_vulnerabilities: usize,
    generate_purl_types: bool,
) -> Result<OutputSBOMs, Box<dyn Error>> {
    let zip_path = input.as_str();

    let entities = concurrent(zip_path).await?;

    let mut missing_vulnerabilities = total_vulnerabilities as i64;
    println!("Output file data gathering");
    let progress_bar = ProgressBar::new(missing_vulnerabilities as u64).with_style(
        ProgressStyle::with_template(PROGRESS_BAR_TEMPLATE).unwrap_or(ProgressStyle::default_bar()),
    );
    let mut cdx_components = vec![];
    let mut spdx_package_information: Vec<PackageInformation> = vec![];

    let mut cves_already_added = HashSet::new();
    let ecosystem_regex = match purl_types.is_empty() {
        false => Regex::new(&format!(
            "^pkg:({})\\/",
            purl_types.into_iter().map(|x| x.to_string()).join("|")
        ))
        .unwrap(),
        true => Regex::new(".*").unwrap(),
    };
    let mut purl_types = HashSet::<String>::new();
    let mut all_purl_cpe_couples = entities
        .clone()
        .into_iter()
        // map the active model into a tuple (PURL, CVE)
        .map(|entity| {
            if generate_purl_types {
                purl_types.insert(
                    entity.purl.as_ref().to_string()
                        // "substring" the PURL type which always starts at the 4th char,
                        // i.e. after 'pkg:' prefix, and ends at the first '/' occurrence
                        [4..entity.purl.as_ref().find("/").unwrap_or(3)]
                        .to_string(),
                );
            }
            (
                String::from(entity.purl.as_ref()),
                String::from(entity.cve.as_ref()),
            )
        })
        // filter out the tuple with purls not within the required ecosystems
        .filter(|entity| ecosystem_regex.is_match(&entity.0))
        .collect_vec();
    if generate_purl_types {
        println!(
            "PURL types found in {} are:\n{:#?}",
            input,
            purl_types.iter().sorted()
        );
    }
    // since dedup works on consecutive elements, the vec must be sorted
    all_purl_cpe_couples.sort();
    // dedup is required because CVE are taken from alias array of different GHSA and
    // associated with the PURL they affect. So it can happen to have two (or more) different GHSAs
    // with the same CVE alias and the same PURL causing the tuple (PURL, CVE) to appear multiple
    // times and hence break the calculations
    all_purl_cpe_couples.dedup();
    while missing_vulnerabilities > 0 {
        all_purl_cpe_couples
            // filter out the tuples with CVEs already added to the output component array
            // because otherwise pkg-B, affected by CVE-1, could be added to the final SBOM
            // even if previously, pkg-A, affected by CVE-1, has been already added: here the
            // algorithm things it added 2 vulnerabilities but it's the same one, i.e. CVE-1,
            // affecting two packages, i.e. pkg-A and pkg-B
            .retain(|entity| !cves_already_added.contains(&entity.1));
        let mut purl_with_all_its_vulnerabilities = HashMap::new();
        all_purl_cpe_couples
            .clone()
            .into_iter()
            .for_each(|(purl, cve)| {
                purl_with_all_its_vulnerabilities
                    .entry(purl)
                    .or_insert_with(Vec::new)
                    .push(cve);
            });
        let next_purl = purl_with_all_its_vulnerabilities
            .iter()
            // map each purl to the tuple (number of vulnerabilities affecting the PURL, PURL)
            .map(|purl_with_cves| (purl_with_cves.1.len(), purl_with_cves.0))
            // filter out the PURL with too many vulnerabilities compared to the missing vulnerabilities
            // to be found in order to fulfill the output SBOM
            .filter(|(number_vulnerabilities, _purl)| {
                *number_vulnerabilities as i64 <= missing_vulnerabilities
            })
            .max();
        if let Some(next_purl) = next_purl {
            missing_vulnerabilities -= next_purl.0 as i64;
            let mut cves_affecting_purl = purl_with_all_its_vulnerabilities[next_purl.1].clone();
            cves_affecting_purl.sort();
            cves_already_added.extend(cves_affecting_purl.clone());
            // create the component for the output SBOM
            let purl = PackageUrl::from_str(next_purl.1).unwrap();
            let package_description =
                format!("{} vulnerabilities {:?}", next_purl.0, cves_affecting_purl);
            let component = ComponentBuilder::default()
                .type_("Library".to_string())
                .name(purl.name())
                .version(purl.version().unwrap_or(""))
                .purl(purl.to_string())
                .description(package_description.as_str())
                .build()
                .unwrap();
            cdx_components.push(component);

            let mut package_information =
                PackageInformation::new(purl.name(), &mut (spdx_package_information.len() as i32));
            package_information.package_version = purl.version().map(|version| version.to_string());
            package_information
                .external_reference
                .push(ExternalPackageReference {
                    reference_category: ExternalPackageReferenceCategory::PackageManager,
                    reference_type: "purl".to_string(),
                    reference_locator: purl.to_string(),
                    reference_comment: Some(package_description),
                });
            spdx_package_information.push(package_information);
            progress_bar.inc(next_purl.0 as u64);
        } else {
            break;
        }
    }
    progress_bar.finish();

    let total_vulnerabilities = total_vulnerabilities - missing_vulnerabilities as usize;
    let total_packages = cdx_components.len();

    let uuid = Uuid::new_v4();
    let sbom_name = format!("{} vulnerabilities", total_vulnerabilities);
    let sbom_version = format!("0.{}.{}", total_vulnerabilities, total_packages);

    let cdx = CycloneDxBuilder::default()
        .bom_format("CycloneDX")
        .spec_version("1.6")
        .version(1)
        .serial_number(uuid.to_string())
        .metadata(Metadata {
            tools: Some(MetadataTools::Variant1(MetadataToolsVariant1::from(vec![
                Tool {
                    name: Some(BOMULATOR_NAME.to_string()),
                    version: Some(BOMULATOR_VERSION.to_string()),
                    ..Tool::default()
                },
            ]))),
            component: Some(
                ComponentBuilder::default()
                    .properties(vec![
                        Property {
                            name: "total_vulnerabilities".to_string(),
                            value: Some(total_vulnerabilities.to_string()),
                        },
                        Property {
                            name: "total_packages".to_string(),
                            value: Some(total_packages.to_string()),
                        },
                    ])
                    .type_("Application".to_string())
                    .name(sbom_name.clone())
                    .version(sbom_version.clone())
                    .build()
                    .unwrap(),
            ),
            ..Metadata::default()
        })
        .components(cdx_components)
        .build()
        .unwrap();

    let cyclonedx =
        serde_json::to_string_pretty(&cdx).expect("CycloneDX JSON serialization failed");

    let package_spdx_identifier = "SPDXRef-0".to_string();
    spdx_package_information.push(PackageInformation {
        package_name: sbom_name.clone(),
        package_spdx_identifier: package_spdx_identifier.clone(),
        package_version: Some(sbom_version),
        package_summary_description: None,
        package_detailed_description: None,
        package_comment: None,
        external_reference: vec![],
        package_attribution_text: vec![],
        annotations: vec![],
        built_date: None,
        release_date: None,
        primary_package_purpose: Some(PrimaryPackagePurpose::Application),
        ..Default::default()
    });
    let spdx = SPDX {
        document_creation_information: DocumentCreationInformation {
            document_name: sbom_name,
            // based upon example in https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#653-examples
            spdx_document_namespace: format!(
                "https://github.com/{}/{}/{}",
                BOMULATOR_NAME, BOMULATOR_VERSION, uuid
            ),
            creation_info: CreationInfo {
                creators: vec![format!("Tool: {}-{}", BOMULATOR_NAME, BOMULATOR_VERSION)],
                creator_comment: Some(format!(
                    "total_vulnerabilities = {}, total_packages = {}",
                    total_vulnerabilities, total_packages
                )),
                ..Default::default()
            },
            document_describes: vec![package_spdx_identifier],
            ..Default::default()
        },
        package_information: spdx_package_information,
        other_licensing_information_detected: vec![],
        file_information: vec![],
        snippet_information: vec![],
        relationships: vec![],
        annotations: vec![],
        spdx_ref_counter: 0,
    };
    let spdx = serde_json::to_string_pretty(&spdx).expect("SPDX JSON serialization failed");

    Ok(OutputSBOMs {
        uuid,
        cyclonedx,
        spdx,
        missing_vulnerabilities,
    })
}

async fn concurrent(zip_path: &str) -> Result<Vec<osv::ActiveModel>, Box<dyn Error>> {
    let zip_data = fs::read(zip_path)?;
    let cursor = Cursor::new(zip_data.clone());
    let mut zip_archive = ZipArchive::new(cursor.clone())?;

    // Collect tasks to process files concurrently
    let mut tasks = Vec::new();
    let decompressed_size = zip_archive.decompressed_size().unwrap_or_default() as usize;
    println!("Input zip file ingestion");
    let progress_bar = ProgressBar::new(zip_archive.len() as u64).with_style(
        ProgressStyle::with_template(PROGRESS_BAR_TEMPLATE).unwrap_or(ProgressStyle::default_bar()),
    );
    // derive the chuck size based on the decompressed zip size and dividing it for the
    // available level of parallelism
    let target_chunk_decompressed_size =
        decompressed_size / available_parallelism().unwrap().get() + 1;
    let mut current_chunk_decompressed_size = 0u64;
    let mut chunk = vec![];
    (0..zip_archive.len()).for_each(|i| {
        // create the chucks dynamically since it's based on the files decompressed size
        if current_chunk_decompressed_size < target_chunk_decompressed_size as u64 {
            current_chunk_decompressed_size += zip_archive.by_index(i).unwrap().size();
            chunk.push(i);
        } else {
            // most performant approach for managing concurrently the same zip file
            // based upon https://github.com/zip-rs/zip-old/issues/14#issuecomment-275921327
            let cursor = Cursor::new(zip_data.clone());
            let chunk_local = chunk.clone();
            let progress_bar = progress_bar.clone();
            let task =
                task::spawn(
                    async move { process_zip_path(cursor, chunk_local, progress_bar).await },
                );
            tasks.push(task);
            current_chunk_decompressed_size = 0;
            chunk = vec![];
        }
    });
    // let's process also the last chunk
    let cursor = Cursor::new(zip_data.clone());
    let chunk_local = chunk.clone();
    let progress_bar_clone = progress_bar.clone();
    let task =
        task::spawn(async move { process_zip_path(cursor, chunk_local, progress_bar_clone).await });
    tasks.push(task);

    // Wait for all tasks to complete
    let mut entities = vec![];
    for task in tasks {
        entities.append(&mut task.await?);
    }
    progress_bar.finish();
    Ok(entities)
}

async fn process_zip_path(
    cursor: Cursor<Vec<u8>>,
    indexes: Vec<usize>,
    progress_bar: ProgressBar,
) -> Vec<osv::ActiveModel> {
    let mut zip_archive = ZipArchive::new(cursor).unwrap();
    let mut entities = vec![];
    let cve_regex = Regex::new("^cve-").unwrap();
    for i in indexes {
        let mut zip_file = zip_archive.by_index(i).unwrap();
        if zip_file.is_file() {
            let mut json_content = String::new();
            zip_file
                .read_to_string(&mut json_content)
                .expect("File from the ZIP file should be readable to a string");
            if let Ok(vuln) = serde_json::from_str::<Osv>(&json_content) {
                if let Some(affected) = vuln.affected {
                    affected.iter().for_each(|vulnerable| {
                        if let Some(package) = &vulnerable.package {
                            if let Some(purl) = &package.purl {
                                // if the affected versions are listed then great, let's use them
                                // inserting a row for each version so that we'll have more
                                // packages available to pick from when composing the SBOMs
                                if let Some(affected_versions) = &vulnerable.versions {
                                    entities.extend(
                                        affected_versions
                                            .iter()
                                            .flat_map(|affected_version| {
                                                let affected_purl =
                                                    format!("{}@{}", purl, affected_version);
                                                if let Some(aliases) = vuln.aliases.clone() {
                                                    aliases
                                                        .into_iter()
                                                        .filter(|alias| {
                                                            cve_regex.is_match(
                                                                alias.to_lowercase().as_str(),
                                                            )
                                                        })
                                                        .map(|alias| osv::ActiveModel {
                                                            cve: ActiveValue::Set(alias.clone()),
                                                            purl: ActiveValue::Set(
                                                                affected_purl.clone(),
                                                            ),
                                                        })
                                                        .collect::<Vec<osv::ActiveModel>>()
                                                } else {
                                                    vec![]
                                                }
                                            })
                                            .collect::<Vec<crate::entities::osv::ActiveModel>>(),
                                    );
                                }
                                // otherwise let's use the value reported in the ranges;
                                else {
                                    vulnerable.ranges.iter().for_each(|range| {
                                        range.iter().for_each(|range| {
                                            range.events.iter().for_each(|event| {
                                                let version = match event.last_affected.as_ref() {
                                                    Some(version) => Some(version),
                                                    None => {
                                                        let introduced_version =
                                                            event.introduced.as_ref();
                                                        if introduced_version
                                                            == Some(&String::from("0"))
                                                        {
                                                            None
                                                        } else {
                                                            introduced_version
                                                        }
                                                    }
                                                };
                                                if let Some(version) = version {
                                                    // DB insert
                                                    let purl = format!("{}@{}", purl, version);
                                                    if cve_regex
                                                        .is_match(vuln.id.to_lowercase().as_str())
                                                    {
                                                        let osv_am = osv::ActiveModel {
                                                            cve: ActiveValue::Set(vuln.id.clone()),
                                                            purl: ActiveValue::Set(purl.clone()),
                                                        };
                                                        entities.push(osv_am);
                                                    }
                                                    if let Some(aliases) = vuln.aliases.clone() {
                                                        for alias in aliases
                                                            .into_iter()
                                                            .filter(|alias| {
                                                                cve_regex.is_match(
                                                                    alias.to_lowercase().as_str(),
                                                                )
                                                            })
                                                            .collect::<Vec<_>>()
                                                        {
                                                            let osv_am = osv::ActiveModel {
                                                                cve: ActiveValue::Set(alias),
                                                                purl: ActiveValue::Set(
                                                                    purl.clone(),
                                                                ),
                                                            };
                                                            entities.push(osv_am);
                                                        }
                                                    }
                                                }
                                            })
                                        })
                                    });
                                }
                            }
                        }
                    })
                }
            }
        }
        progress_bar.inc(1);
    }
    entities
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum PurlType {
    Apk,
    Bitnami,
    Cargo,
    Composer,
    Deb,
    Gem,
    Golang,
    Hackage,
    Hex,
    Maven,
    Npm,
    Nuget,
    Pub,
    Pypi,
    Swift,
}

impl FromStr for PurlType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "apk" => Ok(PurlType::Apk),
            "bitnami" => Ok(PurlType::Bitnami),
            "cargo" => Ok(PurlType::Cargo),
            "composer" => Ok(PurlType::Composer),
            "deb" => Ok(PurlType::Deb),
            "gem" => Ok(PurlType::Gem),
            "golang" => Ok(PurlType::Golang),
            "hackage" => Ok(PurlType::Hackage),
            "hex" => Ok(PurlType::Hex),
            "maven" => Ok(PurlType::Maven),
            "npm" => Ok(PurlType::Npm),
            "nuget" => Ok(PurlType::Nuget),
            "pub" => Ok(PurlType::Pub),
            "pypi" => Ok(PurlType::Pypi),
            "swift" => Ok(PurlType::Swift),
            _ => Err(()),
        }
    }
}

impl Display for PurlType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            PurlType::Apk => "apk".to_string(),
            PurlType::Bitnami => "bitnami".to_string(),
            PurlType::Cargo => "cargo".to_string(),
            PurlType::Composer => "composer".to_string(),
            PurlType::Deb => "deb".to_string(),
            PurlType::Gem => "gem".to_string(),
            PurlType::Golang => "golang".to_string(),
            PurlType::Hackage => "package".to_string(),
            PurlType::Hex => "hex".to_string(),
            PurlType::Maven => "maven".to_string(),
            PurlType::Npm => "npm".to_string(),
            PurlType::Nuget => "nuget".to_string(),
            PurlType::Pub => "pub".to_string(),
            PurlType::Pypi => "pypi".to_string(),
            PurlType::Swift => "swift".to_string(),
        };
        write!(f, "{}", str)
    }
}

/// A schema for describing a vulnerability in an open source package. See also
/// <https://ossf.github.io/osv-schema/>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Osv {
    affected: Option<Vec<Affected>>,
    aliases: Option<Vec<String>>,
    credits: Option<Vec<Credit>>,
    database_specific: Option<HashMap<String, Option<serde_json::Value>>>,
    details: Option<String>,
    id: String,
    modified: String,
    published: Option<String>,
    references: Option<Vec<Reference>>,
    related: Option<Vec<String>>,
    schema_version: Option<String>,
    severity: Option<Vec<O>>,
    summary: Option<String>,
    withdrawn: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Affected {
    database_specific: Option<HashMap<String, Option<serde_json::Value>>>,
    ecosystem_specific: Option<HashMap<String, Option<serde_json::Value>>>,
    package: Option<Package>,
    ranges: Option<Vec<GitRangesRequireARepo>>,
    severity: Option<Vec<O>>,
    versions: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Package {
    ecosystem: String,
    name: String,
    purl: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct GitRangesRequireARepo {
    database_specific: Option<HashMap<String, Option<serde_json::Value>>>,
    events: Vec<EventsMustContainAnIntroducedObjectAndMayContainFixedLastAffectedOrLimitObject>,
    repo: Option<String>,
    #[serde(rename = "type")]
    git_ranges_require_a_repo_type: RangeType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct EventsMustContainAnIntroducedObjectAndMayContainFixedLastAffectedOrLimitObject {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
    limit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RangeType {
    #[serde(rename = "ECOSYSTEM")]
    Ecosystem,
    #[serde(rename = "GIT")]
    Git,
    #[serde(rename = "SEMVER")]
    Semver,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct O {
    score: String,
    #[serde(rename = "type")]
    o_type: SeverityType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SeverityType {
    #[serde(rename = "CVSS_V3")]
    CvssV3,
    #[serde(rename = "CVSS_V4")]
    CvssV4,
    #[serde(rename = "CVSS_V2")]
    CvssV2,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Credit {
    contact: Option<Vec<String>>,
    name: String,
    #[serde(rename = "type")]
    credit_type: Option<CreditType>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CreditType {
    Analyst,
    Coordinator,
    Finder,
    Other,
    #[serde(rename = "REMEDIATION_DEVELOPER")]
    RemediationDeveloper,
    #[serde(rename = "REMEDIATION_REVIEWER")]
    RemediationReviewer,
    #[serde(rename = "REMEDIATION_VERIFIER")]
    RemediationVerifier,
    Reporter,
    Sponsor,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Reference {
    #[serde(rename = "type")]
    reference_type: ReferenceType,
    url: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ReferenceType {
    #[serde(rename = "ADVISORY")]
    Advisory,
    #[serde(rename = "ARTICLE")]
    Article,
    #[serde(rename = "DETECTION")]
    Detection,
    #[serde(rename = "DISCUSSION")]
    Discussion,
    #[serde(rename = "EVIDENCE")]
    Evidence,
    #[serde(rename = "FIX")]
    Fix,
    #[serde(rename = "GIT")]
    Git,
    #[serde(rename = "INTRODUCED")]
    Introduced,
    #[serde(rename = "PACKAGE")]
    Package,
    #[serde(rename = "REPORT")]
    Report,
    #[serde(rename = "WEB")]
    Web,
}

pub struct OutputSBOMs {
    pub uuid: Uuid,
    pub cyclonedx: String,
    pub spdx: String,
    pub missing_vulnerabilities: i64,
}
