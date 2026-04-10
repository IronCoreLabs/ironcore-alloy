mod common;
mod test {
    use crate::common::build_dynamic_library;
    use std::error::Error;
    use std::fs;
    use std::path::Path;

    /// Run all the foreign C# library tests and fail if any of them failed.
    /// WARNING:
    ///   this test modifies the filesystem and expects dotnet SDK to be installed.
    ///   It will copy our dynamic library and generated C# code to the C# project structure.
    #[test]
    fn foreign_tests_csharp() -> Result<(), Box<dyn Error>> {
        use crate::common::generate_csharp_bindings;

        // `cargo test` doesn't build the cdylib targets, so we need to manually build them to make sure they're there
        build_dynamic_library()?;
        // copy the just compiled dynamic library to the C# directory
        let dynamic_library_paths = crate::common::get_dynamic_library_paths()?;
        let csharp_dir = Path::new("csharp");
        for library_file in dynamic_library_paths.iter() {
            fs::copy(
                library_file.clone(),
                csharp_dir.join(library_file.file_name().unwrap()),
            )?;
        }
        // clean stale generated .cs files before regenerating (only generated ones, not our test file)
        for entry in fs::read_dir(csharp_dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "cs")
                && path.file_name().unwrap() != "IroncoreAlloyTest.cs"
            {
                fs::remove_file(&path)?;
            }
        }
        // generate the bindings to go with the just compiled binary
        generate_csharp_bindings(dynamic_library_paths[0].clone(), csharp_dir.to_path_buf())?;
        // run the dotnet test command and print the output as though it were our output
        let mut handle = std::process::Command::new("dotnet")
            .args(["test", "--verbosity", "normal"])
            .current_dir(csharp_dir)
            .spawn()
            .unwrap();
        let exit_code = handle.wait().unwrap();
        assert!(exit_code.success());

        Ok(())
    }
}
