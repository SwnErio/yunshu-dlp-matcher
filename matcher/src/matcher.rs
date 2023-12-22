use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use chrono::Utc;
use evalexpr::{build_operator_tree, ContextWithMutableVariables};
use filesize::PathExt;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};

use crate::{
    fs_error::Error,
    model::{
        agent_model::{DLPFileInfo, DLPFileSecurity, DLPSensitiveFile},
        fs_model::{FileDigitalDictionary, FileScanRule},
        raw_model::{RawScanResult, TRawScanResult},
    },
    utils::common_utils::{md5_file, sha256_file, system_time_to_unix_time},
};

/// Global file security config
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct GlobalFileScanRule {
    pub config_version: String,
    pub file_scan_rules: Vec<FileScanRule>,
    pub file_digital_dictionary: HashMap<i32, FileDigitalDictionary>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct GlobalFileScanFormat {
    pub format: HashMap<String, HashSet<i32>>,
}

impl GlobalFileScanFormat {
    pub fn get_match_types(&self, format_key: String) -> HashSet<i32> {
        self.format.get(&format_key).cloned().unwrap_or_default()
    }
}

struct GlobalConfig {
    file_scan_rule: GlobalFileScanRule,
    file_scan_format: GlobalFileScanFormat,
}

static mut GLOBAL_CONFIG: Option<GlobalConfig> = None;

#[repr(C)]
pub struct FsMatcher {}

impl FsMatcher {
    pub fn init(file_scan_rule: GlobalFileScanRule, file_scan_format: GlobalFileScanFormat) {
        let global_config = GlobalConfig {
            file_scan_rule,
            file_scan_format,
        };
        unsafe {
            GLOBAL_CONFIG = Some(global_config);
        }
    }

    pub fn file_security_check(
        raw_result_string: String,
        matcher_file: &Path,
    ) -> Option<DLPSensitiveFile> {
        info!("[SecurityCheck] check file: {}", matcher_file.display());
        if let Some(ref global_config) = unsafe { &GLOBAL_CONFIG } {
            match serde_json::from_str::<RawScanResult>(&raw_result_string) {
                Ok(raw_result) => {
                    if raw_result.data.is_empty() {
                        return None;
                    }
                    let mut hit_rules = HashSet::<DLPFileSecurity>::new();
                    let scan_rule = &global_config.file_scan_rule;
                    let file_scan_rule = scan_rule.file_scan_rules.clone();
                    let file_digital_dictionary = scan_rule.file_digital_dictionary.clone();

                    // check main data
                    Self::match_rule(
                        matcher_file,
                        &file_scan_rule,
                        &file_digital_dictionary,
                        &raw_result,
                        &mut hit_rules,
                        &global_config.file_scan_format,
                    );

                    // check sub data
                    if let Some(sub_data) = raw_result.sub_data {
                        for raw_result in sub_data {
                            // let file_scan_rule = file_scan_rule_cl.clone();
                            Self::match_rule(
                                matcher_file,
                                &file_scan_rule,
                                &file_digital_dictionary,
                                &raw_result,
                                &mut hit_rules,
                                &global_config.file_scan_format,
                            );
                        }
                    }

                    if hit_rules.is_empty() {
                        None
                    } else {
                        let file_type = raw_result.format;
                        let desc = raw_result.desc;
                        let hit_rules = hit_rules.into_iter().collect::<Vec<DLPFileSecurity>>();
                        match Self::update_file(
                            matcher_file,
                            desc,
                            raw_result_string,
                            file_type,
                            hit_rules,
                        ) {
                            Ok(result) => Some(result),
                            Err(e) => {
                                error!("[SecurityCheck] Failed to update file info: {e}");
                                None
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("[SecurityCheck] Failed to parse raw scan result: {e}");
                    None
                }
            }
        } else {
            error!("[SecurityCheck] GLOBAL_CONFIG not init!");
            None
        }
    }

    fn match_rule(
        matcher_file: &Path,
        file_scan_rule: &Vec<FileScanRule>,
        file_digital_dictionary: &HashMap<i32, FileDigitalDictionary>,
        raw_result: &dyn TRawScanResult,
        hit_rules: &mut HashSet<DLPFileSecurity>,
        scan_format: &GlobalFileScanFormat,
    ) {
        let dlp_type = raw_result.get_dlp_type();
        let format = raw_result.get_format();
        let encrypted = raw_result.need_check_encrypted();
        let hidden = raw_result.need_check_hidden();

        let file_size = matcher_file.size_on_disk().unwrap_or_default();
        let match_types = scan_format.get_match_types(format);

        for rule in file_scan_rule {
            let file_size_range = rule.min_file_size..rule.max_file_size;
            if rule.check_file_encrypted && !encrypted {
                continue;
            }

            if rule.check_file_suffix && !hidden {
                continue;
            }

            if !rule.file_types.is_empty()
                && !rule.file_types.contains(&dlp_type)
                && rule.file_types.intersection(&match_types).next().is_none()
            {
                continue;
            }

            if file_size == 0 || !file_size_range.contains(&file_size) {
                continue;
            }

            if !rule.expr.is_empty() {
                if let Ok(expression) = build_operator_tree(&rule.expr) {
                    let mut context = rule.expr_context.to_owned();
                    context = raw_result.update_context(context, file_digital_dictionary);
                    if rule.md5_check {
                        let file_md5 = md5_file(matcher_file).unwrap_or_default();
                        let _ = context.set_value("md5".to_owned(), file_md5.into());
                    }
                    if let Ok(result) = expression.eval_with_context(&context) {
                        if !result.as_boolean().unwrap_or_default() {
                            continue;
                        }
                    } else {
                        error!(
                            "[Security ID:{}] Failed to evaluate expression on data: {}, context: {context:?}",
                            rule.id, rule.expr
                        );
                        continue;
                    }
                } else {
                    error!(
                        "[Security ID:{}] Failed to build expression on data: {}",
                        rule.id, rule.expr
                    );
                    continue;
                }
            }

            let hit_rule = DLPFileSecurity {
                id: rule.id,
                code: rule.code.to_owned(),
                level: rule.level,
            };
            hit_rules.insert(hit_rule);
        }
    }

    fn update_file(
        file_path: &Path,
        desc: String,
        engine_result: String,
        file_type: String,
        hit_rules: Vec<DLPFileSecurity>,
    ) -> Result<DLPSensitiveFile, Error> {
        if let Ok(md) = file_path.metadata() {
            let access_time = md.accessed().ok().map_or(0, system_time_to_unix_time) as u64;
            let update_time = md.modified().ok().map_or(0, system_time_to_unix_time) as u64;
            let create_time = md.created().ok().map_or(0, system_time_to_unix_time) as u64;
            let file_size = file_path.size_on_disk_fast(&md).unwrap_or_default();
            let file_path_string = file_path.to_str().unwrap_or_default().to_owned();
            let file_name = file_path
                .file_name()
                .unwrap_or_default()
                .to_str()
                .unwrap_or_default()
                .to_owned();
            let file_sha256 = sha256_file(&file_path_string).unwrap_or_default();
            let file_md5 = md5_file(&file_path_string).unwrap_or_default();

            let file_info = DLPFileInfo {
                file_name,
                file_type,
                file_size,
                file_path: file_path_string,
                file_sha256,
                file_md5,
                create_time,
                update_time,
                access_time,
                desc,
            };

            let file_url = "".to_owned();

            let result = DLPSensitiveFile {
                file_info,
                file_securities: hit_rules,
                engine_result,
                file_url,
                found_time: Utc::now().timestamp() as u64,
            };
            Ok(result)
        } else {
            Err(Error::Scanner(format!(
                "Get file meta failed: {}",
                file_path.metadata().unwrap_err()
            )))
        }
    }
}
