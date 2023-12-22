use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
    path::PathBuf,
};

use log::LevelFilter;
use log4rs::{
    append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRollerBuilder,
    append::rolling_file::policy::compound::trigger::size::SizeTrigger,
    append::rolling_file::policy::compound::CompoundPolicy,
    append::rolling_file::RollingFileAppender,
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
    filter::threshold::ThresholdFilter,
};

/// No error
pub const ERR_OK: i32 = 0;
/// Parameter error
pub const ERR_PARAM: i32 = 1;

fn setup_logger(log_path: Option<String>) -> Result<(), String> {
    let log_path = match log_path {
        Some(path) => PathBuf::from(path),
        None => {
            if cfg!(target_os = "windows") {
                std::env::temp_dir().join("YunShu Plugin").join("Logs")
            } else if cfg!(target_os = "macos") {
                PathBuf::from("/opt/.yunshu/logs")
            } else {
                panic!("UNSUPPORTED SYSTEM")
            }
        }
    };

    if !log_path.as_path().exists() {
        std::fs::create_dir_all(&log_path).map_err(|e| format!("{e}"))?;
    }
    let log_path = log_path.join("fs_matcher.log");
    let log_path_pattern = format!("{}.{{}}", log_path.to_string_lossy());

    let size_trigger = SizeTrigger::new(5 * 1024 * 1024);
    let roller_builder = FixedWindowRollerBuilder::default();
    let roller = roller_builder
        .build(&log_path_pattern, 2)
        .map_err(|e| e.to_string())?;

    let compound_policy = CompoundPolicy::new(Box::new(size_trigger), Box::new(roller));
    let rotate_logger = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "[{d(%Y-%m-%d %H:%M:%S)}][{l}][thread-{I}][{t}:{L}]{m}{n}",
        )))
        .build(log_path, Box::new(compound_policy))
        .map_err(|e| e.to_string())?;
    let config = Config::builder()
        .appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(LevelFilter::Info)))
                .build("rotate_logger", Box::new(rotate_logger)),
        )
        .build(
            Root::builder()
                .appender("rotate_logger")
                .build(LevelFilter::Info),
        )
        .map_err(|e| e.to_string())?;
    // init panic record
    log_panics::Config::new()
        .backtrace_mode(log_panics::BacktraceMode::Resolved)
        .install_panic_hook();
    let _ = log4rs::init_config(config).map_err(|e| e.to_string())?;
    Ok(())
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn init_logger(plog_path: *const c_char) -> i32 {
    let result = if let Ok(log_path) = unsafe { CStr::from_ptr(plog_path).to_str() } {
        setup_logger(Some(log_path.to_string())).is_ok()
    } else {
        setup_logger(None).is_ok()
    };

    if result {
        ERR_OK
    } else {
        ERR_PARAM
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn init_matcher(
    pfile_scan_rule: *const c_char,
    pfile_scan_format: *const c_char,
) -> i32 {
    let str_file_scan_rule = match unsafe { CStr::from_ptr(pfile_scan_rule).to_str() } {
        Ok(str) => str,
        Err(_) => return ERR_PARAM,
    };

    let str_file_scan_format = match unsafe { CStr::from_ptr(pfile_scan_format).to_str() } {
        Ok(str) => str,
        Err(_) => return ERR_PARAM,
    };

    matcher_lib::init_matcher(str_file_scan_rule, str_file_scan_format);
    ERR_OK
}

// #[allow(clippy::not_unsafe_ptr_arg_deref)]
// #[no_mangle]
// pub extern "C" fn drop_matcher(pmatcher: *mut c_void) {
//     unsafe { pmatcher.drop_in_place() }
// }

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn match_rule(
    praw_result: *const c_char,
    pfile_path: *const c_char,
    ppmatch_result: *mut *mut c_char,
) -> i32 {
    let str_raw_result = match unsafe { CStr::from_ptr(praw_result).to_str() } {
        Ok(str) => str,
        Err(_) => return ERR_PARAM,
    };

    let str_file_path = match unsafe { CStr::from_ptr(pfile_path).to_str() } {
        Ok(str) => str,
        Err(_) => return ERR_PARAM,
    };

    let match_result = matcher_lib::match_rule(str_raw_result, str_file_path);
    match CString::new(match_result) {
        Ok(cstring_match_result) => unsafe { *ppmatch_result = cstring_match_result.into_raw() },
        Err(_) => return ERR_PARAM,
    }

    ERR_OK
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn drop_result(presult: *mut c_char) {
    unsafe {
        let _ = CString::from_raw(presult);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::{CStr, CString},
        os::raw::c_char,
    };

    use crate::{drop_result, ERR_OK, ERR_PARAM};

    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    #[no_mangle]
    pub extern "C" fn fs_test(file_path: *const c_char, result: *mut *mut c_char) -> i32 {
        if let Ok(_path) = unsafe { CStr::from_ptr(file_path).to_str() } {
            let response = "The response".to_owned();
            let c_response = CString::new(response).unwrap();
            let response_ptr = c_response.into_raw();
            unsafe {
                *result = response_ptr;
            }
            ERR_OK
        } else {
            ERR_PARAM
        }
    }

    #[test]
    fn test_raw_pointer() {
        let cstring = CString::new("The path").unwrap();
        let ptr = cstring.as_ptr();
        let mut result_ptr = std::ptr::null_mut();
        let result_ptr_ptr = &mut result_ptr as *mut *mut c_char;
        println!("fs_test");
        fs_test(ptr, result_ptr_ptr);
        println!("fs_test over");
        unsafe {
            let response = CStr::from_ptr(result_ptr).to_str().unwrap();
            println!("{}", response);
            drop_result(result_ptr);
        }
    }

    // #[test]
    // fn test_pass_raw_pointer() {
    //     let p1 = CString::new("p1p1p1p1p1").unwrap();
    //     let p2 = CString::new("p2p2p2p2p2").unwrap();
    //     let mut pmatcher = std::ptr::null_mut();
    //     let ppmatcher = &mut pmatcher;
    //     init_matcher(p1.as_ptr(), p2.as_ptr(), ppmatcher);
    //     println!("ppmatcher is null? {}", ppmatcher.is_null());
    //     unsafe {
    //         let pmatcher = *ppmatcher;
    //         println!("pmatcher is null? {}", pmatcher.is_null());
    //         let ref_matcher = &*(pmatcher as *mut Matcher);
    //         ref_matcher.test();
    //         let result = ref_matcher
    //             .file_security_check("raw_result_string".to_owned(), &PathBuf::from("value"));
    //         println!("ptr invoke: {result:?}");
    //     }
    // }
}
