use std::collections::{HashMap, HashSet};

use evalexpr::{
    ContextWithMutableFunctions, ContextWithMutableVariables, EvalexprError, Function,
    HashMapContext, Value,
};
use serde::{Deserialize, Serialize};

use super::fs_model::FileDigitalDictionary;

pub trait TRawScanResult {
    fn update_context(
        &self,
        context: HashMapContext,
        dictionary: &HashMap<i32, FileDigitalDictionary>,
    ) -> HashMapContext;
    fn get_dlp_type(&self) -> i32;
    fn get_format(&self) -> String;
    fn need_check_encrypted(&self) -> bool;
    fn need_check_hidden(&self) -> bool;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RawScanResult {
    #[serde(rename = "categoryId")]
    pub category_id: i32,
    #[serde(default)]
    pub desc: String,
    pub format: String,
    pub data: Vec<RawScanResultData>,
    #[serde(default)]
    pub encrypted: i32,
    #[serde(default)]
    pub hidden: i32,
    #[serde(rename = "subFileData")]
    pub sub_data: Option<Vec<RawScanResultSubData>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RawScanResultSubData {
    #[serde(rename = "categoryId")]
    pub category_id: i32,
    #[serde(default)]
    pub desc: String,
    pub format: String,
    pub data: Vec<RawScanResultData>,
    #[serde(default)]
    pub encrypted: i32,
    #[serde(default)]
    pub hidden: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RawScanResultData {
    pub id: i32,
    #[serde(default)]
    pub length: i32,
    pub location: String,
}

impl TRawScanResult for RawScanResult {
    fn update_context(
        &self,
        mut context: HashMapContext,
        dictionary: &HashMap<i32, FileDigitalDictionary>,
    ) -> HashMapContext {
        let mut temp_map = HashMap::<String, i32>::new();
        let mut mapped_key_set = HashSet::<String>::new();

        for item in &self.data {
            if let Some(entry) = dictionary.get(&item.id) {
                let mapped_key = format!("{}{}", item.location, entry.target_id);
                if !mapped_key_set.contains(&mapped_key) {
                    if let Some(current_value) = temp_map.get(&mapped_key) {
                        let new_one = current_value + entry.value;
                        if new_one >= entry.target_threshold {
                            mapped_key_set.insert(mapped_key.clone());
                            let _ = context.set_value(mapped_key, 1.into());
                        } else {
                            temp_map.insert(mapped_key, new_one);
                        }
                    } else {
                        temp_map.insert(mapped_key, entry.value);
                    }
                }
            }

            let key = format!("{}{}", item.location, item.id);
            let _ = context.set_value(key, (item.length as i64).into());
        }
        let _ = context.set_function(
            "cvtBoolToInt".to_owned(),
            Function::new(|argument| {
                if let Ok(boolean) = argument.as_boolean() {
                    if boolean {
                        Ok(Value::Int(1))
                    } else {
                        Ok(Value::Int(0))
                    }
                } else {
                    Err(EvalexprError::expected_boolean(argument.clone()))
                }
            }),
        );
        context
    }

    fn get_dlp_type(&self) -> i32 {
        self.category_id
    }

    fn get_format(&self) -> String {
        self.format.clone()
    }

    fn need_check_encrypted(&self) -> bool {
        self.encrypted != 0
    }

    fn need_check_hidden(&self) -> bool {
        self.hidden != 0
    }
}

impl TRawScanResult for RawScanResultSubData {
    fn update_context(
        &self,
        mut context: HashMapContext,
        dictionary: &HashMap<i32, FileDigitalDictionary>,
    ) -> HashMapContext {
        let mut temp_map = HashMap::<String, i32>::new();
        let mut mapped_key_set = HashSet::<String>::new();

        for item in &self.data {
            if let Some(entry) = dictionary.get(&item.id) {
                let mapped_key = format!("{}{}", item.location, entry.target_id);
                if !mapped_key_set.contains(&mapped_key) {
                    if let Some(current_value) = temp_map.get(&mapped_key) {
                        let new_one = current_value + entry.value;
                        if new_one >= entry.target_threshold {
                            mapped_key_set.insert(mapped_key.clone());
                            let _ = context.set_value(mapped_key, 1.into());
                        } else {
                            temp_map.insert(mapped_key, new_one);
                        }
                    } else {
                        temp_map.insert(mapped_key, entry.value);
                    }
                }
            }

            let key = format!("{}{}", item.location, item.id);
            let _ = context.set_value(key, (item.length as i64).into());
        }
        let _ = context.set_function(
            "cvtBoolToInt".to_owned(),
            Function::new(|argument| {
                if let Ok(boolean) = argument.as_boolean() {
                    if boolean {
                        Ok(Value::Int(1))
                    } else {
                        Ok(Value::Int(0))
                    }
                } else {
                    Err(EvalexprError::expected_boolean(argument.clone()))
                }
            }),
        );
        context
    }

    fn get_dlp_type(&self) -> i32 {
        self.category_id
    }

    fn get_format(&self) -> String {
        self.format.clone()
    }

    fn need_check_encrypted(&self) -> bool {
        self.encrypted != 0
    }

    fn need_check_hidden(&self) -> bool {
        self.hidden != 0
    }
}
