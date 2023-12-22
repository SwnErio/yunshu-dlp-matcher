use std::path::PathBuf;

use fs_error::Error;
use log::info;
use matcher::{FsMatcher, GlobalFileScanFormat, GlobalFileScanRule};

pub mod fs_error;
pub mod matcher;
mod model;
mod utils;

const VERSION: &str = "165d4f07-f5e7-4dca-819c-8b0f7a440d1e";
const DATE: &str = "2023.12.23";

pub fn init_matcher(str_file_scan_rule: &str, str_file_scan_format: &str) {
    info!("[Version] Matcher lib version info: {DATE} (build: {VERSION})");
    info!("[Init] init matcher with RULE:\n{str_file_scan_rule}");
    info!("[Init] init matcher with FORMAT:\n{str_file_scan_format}");
    let file_scan_rule =
        serde_json::from_str::<GlobalFileScanRule>(str_file_scan_rule).unwrap_or_default();
    let file_scan_format =
        serde_json::from_str::<GlobalFileScanFormat>(str_file_scan_format).unwrap_or_default();
    FsMatcher::init(file_scan_rule, file_scan_format)
}

pub fn match_rule(str_raw_result: &str, str_file_path: &str) -> String {
    if let Some(result) =
        FsMatcher::file_security_check(str_raw_result.to_owned(), &PathBuf::from(str_file_path))
    {
        serde_json::to_string(&result).unwrap_or_default()
    } else {
        String::default()
    }
}
