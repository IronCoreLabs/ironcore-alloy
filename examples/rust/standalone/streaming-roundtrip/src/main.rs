//! Streaming standard encryption to and from files.
//!
//! Unlike the one-shot `encrypt`/`decrypt` (which hold the whole document in memory), the streaming
//! API processes a large payload in fixed-size chunks, so neither encryption nor decryption ever
//! needs the entire file resident. Here we stream a file through encryption to disk and back, in
//! 64 KiB chunks.
//!
//! The streamed output is byte-identical to the one-shot V5 format, so a streamed file is just a
//! normal encrypted document: it could equally be decrypted with the one-shot API, and vice versa.

use std::{
    collections::HashMap,
    env,
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
};

use ironcore_alloy::{
    AlloyMetadata, EncryptedBytes, Secret, Standalone, TenantId,
    errors::AlloyError,
    standalone::config::{StandaloneConfiguration, StandaloneSecret, StandardSecrets},
    standard::{EdekWithKeyIdHeader, StandardDocumentOps},
    streaming::DEFAULT_CHUNK_SIZE,
};

#[tokio::main]
async fn main() {
    let standalone_secret =
        env::var("STANDALONE_SECRET").expect("STANDALONE_SECRET env variable must be set.");

    let config = StandaloneConfiguration::new(
        StandardSecrets::new(
            Some(1),
            vec![StandaloneSecret::new(
                1,
                Secret::new(standalone_secret.as_bytes().to_vec()).unwrap(),
            )],
        )
        .unwrap(),
        HashMap::new(),
        HashMap::new(),
    );

    let standalone = Standalone::new(&config);
    let metadata = AlloyMetadata::new_simple(TenantId("tenant".to_string()));

    // Create a sample input file if one doesn't exist, so the example is self-contained. In a real
    // program this would be whatever large file you want to protect.
    let input_path = "plaintext.bin";
    if !std::path::Path::new(input_path).exists() {
        // 5 MiB of easily-verifiable data (many streaming chunks).
        let data: Vec<u8> = (0..5 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        fs::write(input_path, &data).expect("Failed to write sample input file.");
    }

    // --- Streaming encrypt: plaintext.bin -> plaintext.bin.enc (+ the EDEK in plaintext.bin.edek) ---
    let edek = encrypt_file(&standalone, &metadata, input_path, "plaintext.bin.enc").await;
    fs::write("plaintext.bin.edek", &edek.0.0).expect("Failed to write EDEK file.");
    println!("Encrypted {input_path} -> plaintext.bin.enc (EDEK stored in plaintext.bin.edek)");

    // --- Streaming decrypt: plaintext.bin.enc (+ .edek) -> decrypted.bin ---
    let stored_edek = EdekWithKeyIdHeader(EncryptedBytes(
        fs::read("plaintext.bin.edek").expect("Failed to read EDEK file."),
    ));
    decrypt_file(
        &standalone,
        &metadata,
        "plaintext.bin.enc",
        stored_edek,
        "decrypted.bin",
    )
    .await;
    println!("Decrypted plaintext.bin.enc -> decrypted.bin");

    // Verify the round trip.
    let original = fs::read(input_path).unwrap();
    let decrypted = fs::read("decrypted.bin").unwrap();
    assert_eq!(
        original, decrypted,
        "Decrypted file did not match the original!"
    );
    println!(
        "Success: decrypted.bin matches {input_path} ({} bytes).",
        original.len()
    );
}

/// Stream-encrypt `input_path` to `output_path`, returning the EDEK to store alongside it.
///
/// The EDEK is available immediately from the encryptor; the streamed output is the ciphertext
/// chunks followed by the authentication tag emitted by `finish`.
async fn encrypt_file(
    standalone: &Standalone,
    metadata: &AlloyMetadata,
    input_path: &str,
    output_path: &str,
) -> EdekWithKeyIdHeader {
    let encryptor = standalone
        .standard()
        .create_streaming_encryptor(metadata)
        .await
        .expect("Failed to create streaming encryptor.");

    let mut reader = BufReader::new(File::open(input_path).expect("Failed to open input file."));
    let mut writer =
        BufWriter::new(File::create(output_path).expect("Failed to create output file."));

    let mut buffer = vec![0u8; DEFAULT_CHUNK_SIZE];
    loop {
        let read = reader.read(&mut buffer).expect("Failed to read input chunk.");
        if read == 0 {
            break;
        }
        let ciphertext = encryptor
            .encrypt_chunk(buffer[..read].to_vec())
            .expect("Failed to encrypt chunk.");
        writer
            .write_all(&ciphertext)
            .expect("Failed to write ciphertext chunk.");
    }
    // Flush the final bytes and the authentication tag.
    let tag = encryptor.finish().expect("Failed to finalize encryption.");
    writer.write_all(&tag).expect("Failed to write final bytes.");
    writer.flush().expect("Failed to flush output file.");

    encryptor.edek()
}

/// Stream-decrypt `input_path` to `output_path` using `edek`.
///
/// IMPORTANT: streaming decrypt releases plaintext chunks *before* the authentication tag is
/// verified (the tag is at the very end of the stream). We therefore write to a temporary file and
/// only commit it — rename it into place — once `finish` confirms the tag. If verification fails the
/// temp file is deleted, so unverified plaintext is never exposed as the real output. Any program
/// that acts on streamed plaintext as it arrives must be able to roll back like this on failure.
async fn decrypt_file(
    standalone: &Standalone,
    metadata: &AlloyMetadata,
    input_path: &str,
    edek: EdekWithKeyIdHeader,
    output_path: &str,
) {
    let decryptor = standalone
        .standard()
        .create_streaming_decryptor(edek, metadata)
        .await
        .expect("Failed to create streaming decryptor.");

    let mut reader =
        BufReader::new(File::open(input_path).expect("Failed to open encrypted file."));
    let temp_path = format!("{output_path}.tmp");
    let mut writer =
        BufWriter::new(File::create(&temp_path).expect("Failed to create temp output file."));

    // Run the decrypt loop, returning any authentication error so the caller can roll back.
    let mut buffer = vec![0u8; DEFAULT_CHUNK_SIZE];
    let result: Result<(), AlloyError> = (|| {
        loop {
            let read = reader.read(&mut buffer).expect("Failed to read encrypted chunk.");
            if read == 0 {
                break;
            }
            // UNVERIFIED plaintext: written only to the temp file, not yet trusted.
            let plaintext = decryptor.decrypt_chunk(buffer[..read].to_vec())?;
            writer
                .write_all(&plaintext)
                .expect("Failed to write plaintext chunk.");
        }
        // Verify the tag. An error here means everything written so far was never authenticated.
        let remaining = decryptor.finish()?;
        writer
            .write_all(&remaining)
            .expect("Failed to write final plaintext.");
        writer.flush().expect("Failed to flush temp file.");
        Ok(())
    })();

    match result {
        // Authenticated: commit the temp file as the real output.
        Ok(()) => fs::rename(&temp_path, output_path).expect("Failed to commit decrypted file."),
        // Authentication failed: discard the unverified plaintext entirely.
        Err(e) => {
            let _ = fs::remove_file(&temp_path);
            panic!("Decryption failed authentication; discarded unverified output: {e}");
        }
    }
}
