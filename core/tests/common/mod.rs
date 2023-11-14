use std::{
    env,
    error::Error,
    path::PathBuf,
    process::{Command, ExitStatus, Stdio},
};

use uniffi::TargetLanguage;

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
                    .starts_with("libcloaked_ai")
        }) {
            Some(path)
        } else {
            None
        }
    })
    .collect::<Vec<_>>();
    Ok(paths)
}
pub(crate) fn generate_bindings(
    library_path: PathBuf,
    out_dir: PathBuf,
    language: TargetLanguage,
) -> Result<(), Box<dyn Error>> {
    let camino_lib_path = camino::Utf8PathBuf::from_path_buf(library_path).unwrap();
    let camino_out_dir = camino::Utf8PathBuf::from_path_buf(out_dir).unwrap();
    uniffi_bindgen::library_mode::generate_bindings(
        &camino_lib_path,
        None,
        &[language],
        &camino_out_dir,
        true,
    )?;

    Ok(())
}
