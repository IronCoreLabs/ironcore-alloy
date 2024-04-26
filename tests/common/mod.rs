#![allow(dead_code)]

use ironcore_alloy::{
    errors::AlloyError, saas_shield::config::SaasShieldConfiguration, SaasShield,
};
use std::{
    env,
    error::Error,
    path::PathBuf,
    process::{Command, ExitStatus, Stdio},
    sync::Arc,
};
use uniffi_bindgen::BindingGenerator;

pub type TestResult = Result<(), AlloyError>;

pub fn get_client() -> Arc<SaasShield> {
    let config = SaasShieldConfiguration::new(
        "http://localhost:32804".to_string(),
        "0WUaXesNgbTAuLwn".to_string(),
        false,
        Some(1.1),
    )
    .unwrap();
    SaasShield::new(&config)
}

pub(crate) fn build_dynamic_library() -> Result<ExitStatus, Box<dyn Error>> {
    let args: &[&str] = if cfg!(debug_assertions) {
        &["build", "--lib"]
    } else {
        &["build", "--release", "--lib"]
    };
    let mut cmd = Command::new("cargo")
        .args(args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let status = cmd.wait()?;
    Ok(status)
}
pub(crate) fn get_dynamic_library_paths() -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let paths = std::fs::read_dir(
        // look up two dirs from the currently running tests to find our target dir
        env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap(),
    )?
    // Filter out all those directory entries which couldn't be read
    .filter_map(|res| res.ok())
    // Map the directory entries to paths
    .map(|dir_entry| dir_entry.path())
    // Filter out all paths with extensions other than `so` or `dylib`
    .filter_map(|path| {
        if path.extension().map_or(false, |ext| {
            (ext == "dylib" || ext == "so")
                && path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("libironcore_alloy")
        }) {
            Some(path)
        } else {
            None
        }
    })
    .collect::<Vec<_>>();
    Ok(paths)
}

pub(crate) fn generate_bindings<T: BindingGenerator>(
    library_path: PathBuf,
    out_dir: PathBuf,
    language: T,
) -> Result<(), Box<dyn Error>> {
    let camino_lib_path = camino::Utf8PathBuf::from_path_buf(library_path).unwrap();
    let camino_out_dir = camino::Utf8PathBuf::from_path_buf(out_dir).unwrap();
    uniffi_bindgen::library_mode::generate_bindings(
        &camino_lib_path,
        None,
        &language,
        None,
        &camino_out_dir,
        true,
    )?;

    Ok(())
}
