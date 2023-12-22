use std::{
    fs::File,
    io::copy,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use md5::Md5;
use sha2::{Digest, Sha256};

use crate::Error;

pub fn sha256_file<P: AsRef<Path>>(file_name: P) -> Result<String, Error> {
    let mut file = File::open(file_name)?;
    let mut hasher = Sha256::new();
    let _ = copy(&mut file, &mut hasher)?;
    let hash = hasher.finalize();
    let hash_vec = hash.to_vec();
    let hash_string = hex::encode(&hash_vec[..]);
    Ok(hash_string)
}

pub fn md5_file<P: AsRef<Path>>(file_name: P) -> Result<String, Error> {
    let mut file = File::open(file_name)?;
    let mut hasher = Md5::new();
    let _ = copy(&mut file, &mut hasher)?;
    let hash = hasher.finalize();
    let hash_vec = hash.to_vec();
    let hash_string = hex::encode(&hash_vec[..]);
    Ok(hash_string)
}

pub fn system_time_to_unix_time(tm: SystemTime) -> i64 {
    tm.duration_since(UNIX_EPOCH)
        .ok()
        .map_or(0, |t| t.as_secs() as i64)
}
