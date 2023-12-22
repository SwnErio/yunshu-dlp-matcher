use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct DLPFileSecurity {
    pub id: i32,
    pub code: String,
    #[serde(skip)]
    pub level: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DLPFileInfo {
    #[serde(rename = "name")]
    pub file_name: String,
    #[serde(rename = "type")]
    pub file_type: String,
    #[serde(rename = "size")]
    pub file_size: u64,
    #[serde(rename = "path")]
    pub file_path: String,
    #[serde(rename = "sha256_hash")]
    pub file_sha256: String,
    #[serde(rename = "md5_hash")]
    pub file_md5: String,
    pub create_time: u64,
    pub update_time: u64,
    #[serde(rename = "visit_time")]
    pub access_time: u64,
    #[serde(skip, default)]
    pub desc: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DLPSensitiveFile {
    #[serde(rename = "file")]
    pub file_info: DLPFileInfo,
    pub file_securities: Vec<DLPFileSecurity>,
    pub engine_result: String,
    pub file_url: String,
    pub found_time: u64,
}
