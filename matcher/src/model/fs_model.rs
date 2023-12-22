use std::collections::HashSet;

use evalexpr::HashMapContext;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileScanRule {
    pub id: i32,
    pub code: String,
    pub level: i32,
    pub file_types: HashSet<i32>,
    pub min_file_size: u64,
    pub max_file_size: u64,
    pub check_file_encrypted: bool,
    pub check_file_suffix: bool,
    pub expr: String,
    pub expr_context: HashMapContext,
    pub md5_check: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileDigitalDictionary {
    pub target_id: i32,
    pub target_threshold: i32,
    pub value: i32,
}
