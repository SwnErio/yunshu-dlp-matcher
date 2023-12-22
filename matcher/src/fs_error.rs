use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("scanner error: {0}")]
    Scanner(String),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
}
