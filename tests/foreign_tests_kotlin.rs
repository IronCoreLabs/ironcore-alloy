mod common;
mod test {
    use crate::common::build_dynamic_library;
    use std::error::Error;
    use std::fs;
    use std::path::Path;

    /// Run all the foreign Kotlin library tests and fail if any of them failed.
    /// WARNING:
    ///   this test modifies the filesystem and expects the full Kotlin project dependencies.
    ///   It will copy our dynamic library and generated Kotlin code to the Kotlin project structure.
    #[test]
    fn foreign_tests_kotlin() -> Result<(), Box<dyn Error>> {
        use crate::common::generate_bindings;

        // `cargo test` doesn't build the cdylib targets, so we need to manually build them to make sure they're there
        build_dynamic_library()?;
        // copy the just compiled dynamic library to the Kotlin directory
        let dynamic_library_paths = crate::common::get_dynamic_library_paths()?;
        let kotlin_dir = Path::new("kotlin");
        let main_resources_path = kotlin_dir.join(Path::new("src/main/resources/"));
        let main_src_path = kotlin_dir.join(Path::new("src/main/kotlin/"));
        for library_file in dynamic_library_paths.iter() {
            fs::copy(
                library_file.clone(),
                main_resources_path.join(library_file.file_name().unwrap()),
            )?;
        }
        println!("{:?}", main_src_path);
        // generate the bindings to go with the just compiled binary
        generate_bindings(
            dynamic_library_paths[0].clone(),
            main_src_path,
            uniffi::KotlinBindingGenerator,
        )?;
        // run the test command and print the output as though it were our output
        let mut handle = std::process::Command::new("./gradlew")
            .args(["test"])
            .current_dir(kotlin_dir)
            .spawn()
            .unwrap();
        let exit_code = handle.wait().unwrap();
        assert!(exit_code.success());

        Ok(())
    }
}
