mod common;

mod test {
    use std::{error::Error, fs, path::Path, process::Command};

    use crate::common::{build_dynamic_library, generate_bindings, get_dynamic_library_paths};

    /// Run all the foreign Python library tests and fail if any of them failed.
    /// WARNING:
    ///   this test modifies the filesystem and expects the full Python project dependencies.
    ///   It will copy our dynamic library and generated Python code to the Python project structure.
    #[test]
    fn foreign_tests_py() -> Result<(), Box<dyn Error>> {
        use std::io::Write;

        // `cargo test` doesn't build the cdylib targets, so we need to manually build them to make sure they're there
        build_dynamic_library()?;
        // copy the just compiled dynamic library to the python directory
        let dynamic_library_paths = get_dynamic_library_paths()?;
        let python_dir = Path::new("python/cloaked-ai/");
        let python_module_dir = python_dir.join(Path::new("cloaked_ai/"));
        for library_file in dynamic_library_paths.iter() {
            fs::copy(
                library_file.clone(),
                python_module_dir.join(library_file.file_name().unwrap()),
            )?;
        }
        // generate the bindings to go with the just compiled binary
        generate_bindings(
            dynamic_library_paths[0].clone(),
            python_module_dir,
            uniffi::TargetLanguage::Python,
        )?;
        // run the hatch test command and print the output as though it were our output
        let o = Command::new("hatch")
            .args(["run", "test", "--color=yes"])
            .current_dir(python_dir)
            .output()
            .unwrap();
        std::io::stdout().write_all(&o.stdout)?;
        std::io::stderr().write_all(&o.stderr)?;
        assert!(o.status.success());

        Ok(())
    }
}
