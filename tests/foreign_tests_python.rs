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
        // `cargo test` doesn't build the cdylib targets, so we need to manually build them to make sure they're there
        build_dynamic_library()?;
        // copy the just compiled dynamic library to the python directory
        let dynamic_library_paths = get_dynamic_library_paths()?;
        let python_dir = Path::new("python/ironcore-alloy/");
        let python_module_dir = python_dir.join(Path::new("ironcore_alloy/"));
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
            uniffi::PythonBindingGenerator,
        )?;
        // run the hatch test command and print the output as though it were our output
        let mut handle = Command::new("hatch")
            .args(["run", "test:test", "--color=yes", "-s"])
            .current_dir(python_dir)
            .spawn()
            .unwrap();
        let exit_code = handle.wait().unwrap();
        assert!(exit_code.success());

        Ok(())
    }
}
