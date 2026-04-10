#![allow(dead_code)]

use ironcore_alloy::{
    SaasShield, errors::AlloyError, saas_shield::config::SaasShieldConfiguration,
};
use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::Arc,
};
use uniffi_bindgen::{BindgenLoader, BindgenPaths};

pub type TestResult = Result<(), AlloyError>;

pub fn get_client() -> Arc<SaasShield> {
    let http_client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(false)
        .build()
        .expect("Failed to create test reqwest client.");
    let config = SaasShieldConfiguration::new(
        "http://localhost:32804".to_string(),
        "0WUaXesNgbTAuLwn".to_string(),
        Some(1.1),
        Arc::new(http_client),
        true,
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
        if path.extension().is_some_and(|ext| {
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

/// Removes all files in a generated bindings directory to prevent stale files
/// from previous versions causing compilation issues.
pub(crate) fn clean_generated_dir(dir: &Path) -> Result<(), Box<dyn Error>> {
    if dir.exists() {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_file() {
                fs::remove_file(&path)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn create_bindgen_loader() -> Result<BindgenLoader, Box<dyn Error>> {
    let mut paths = BindgenPaths::default();
    paths.add_cargo_metadata_layer(false)?;
    Ok(BindgenLoader::new(paths))
}

pub(crate) fn generate_kotlin_bindings(
    library_path: PathBuf,
    out_dir: PathBuf,
) -> Result<(), Box<dyn Error>> {
    let camino_lib_path = camino::Utf8PathBuf::from_path_buf(library_path).unwrap();
    let camino_out_dir = camino::Utf8PathBuf::from_path_buf(out_dir).unwrap();
    uniffi_bindgen::bindings::generate(uniffi_bindgen::bindings::GenerateOptions {
        languages: vec![uniffi_bindgen::bindings::TargetLanguage::Kotlin],
        source: camino_lib_path,
        out_dir: camino_out_dir,
        format: false,
        ..Default::default()
    })?;
    Ok(())
}

pub(crate) fn generate_python_bindings(
    library_path: PathBuf,
    out_dir: PathBuf,
) -> Result<(), Box<dyn Error>> {
    let camino_lib_path = camino::Utf8PathBuf::from_path_buf(library_path).unwrap();
    let camino_out_dir = camino::Utf8PathBuf::from_path_buf(out_dir).unwrap();
    uniffi_bindgen::bindings::generate(uniffi_bindgen::bindings::GenerateOptions {
        languages: vec![uniffi_bindgen::bindings::TargetLanguage::Python],
        source: camino_lib_path,
        out_dir: camino_out_dir,
        format: false,
        ..Default::default()
    })?;
    Ok(())
}

pub(crate) fn generate_csharp_bindings(
    library_path: PathBuf,
    out_dir: PathBuf,
) -> Result<(), Box<dyn Error>> {
    let camino_lib_path = camino::Utf8PathBuf::from_path_buf(library_path).unwrap();
    let camino_out_dir = camino::Utf8PathBuf::from_path_buf(out_dir.clone()).unwrap();
    // uniffi-bindgen-cs uses a CLI-driven API, so we run it as a subprocess
    let status = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "uniffi-bindgen-cs",
            "--",
            "--library",
            camino_lib_path.as_str(),
            "--out-dir",
            camino_out_dir.as_str(),
            "--no-format",
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    if !status.success() {
        return Err("uniffi-bindgen-cs failed".into());
    }
    // Post-process generated bindings to fix C# codegen issues
    let cs_file = out_dir.join("ironcore_alloy.cs");
    let fix_status = Command::new("python3")
        .args([
            out_dir.join("fix_bindings.py").to_str().unwrap(),
            cs_file.to_str().unwrap(),
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    if !fix_status.success() {
        return Err("fix_bindings.py failed".into());
    }
    Ok(())
}

pub(crate) fn generate_java_bindings(
    library_path: PathBuf,
    out_dir: PathBuf,
) -> Result<(), Box<dyn Error>> {
    let loader = create_bindgen_loader()?;
    let camino_lib_path = camino::Utf8PathBuf::from_path_buf(library_path).unwrap();
    let camino_out_dir = camino::Utf8PathBuf::from_path_buf(out_dir).unwrap();
    uniffi_bindgen_java::generate(
        &loader,
        &uniffi_bindgen_java::GenerateOptions {
            source: camino_lib_path,
            out_dir: camino_out_dir,
            format: false,
            crate_filter: None,
        },
    )?;
    Ok(())
}
