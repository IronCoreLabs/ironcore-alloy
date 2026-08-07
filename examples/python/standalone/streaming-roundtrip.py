import ironcore_alloy as alloy
import os
import asyncio

# Recommended streaming chunk size (64 KiB). Streaming processes the payload in fixed-size chunks so
# the whole file never has to be held in memory at once.
CHUNK_SIZE = 64 * 1024


async def encrypt_file(sdk, metadata, input_path, output_path):
    """Stream-encrypt input_path -> output_path, returning the EDEK to store alongside it.

    The EDEK is available immediately from the encryptor; the streamed output is the ciphertext
    chunks followed by the authentication tag emitted by finish().
    """
    encryptor = await sdk.standard().create_streaming_encryptor(metadata)
    with open(input_path, "rb") as reader, open(output_path, "wb") as writer:
        while chunk := reader.read(CHUNK_SIZE):
            writer.write(encryptor.encrypt_chunk(chunk))
        # Flush the final bytes and the authentication tag.
        writer.write(encryptor.finish())
    return encryptor.edek()


async def decrypt_file(sdk, metadata, input_path, edek, output_path):
    """Stream-decrypt input_path -> output_path using edek.

    IMPORTANT: streaming decrypt releases plaintext chunks *before* the authentication tag is
    verified (the tag is at the very end of the stream). We therefore write to a temporary file and
    only commit it -- rename it into place -- once finish() confirms the tag. If verification fails
    the temp file is deleted, so unverified plaintext is never exposed as the real output. Any
    program that acts on streamed plaintext as it arrives must be able to roll back like this on
    failure.
    """
    decryptor = await sdk.standard().create_streaming_decryptor(edek, metadata)
    temp_path = output_path + ".tmp"
    try:
        with open(input_path, "rb") as reader, open(temp_path, "wb") as writer:
            while chunk := reader.read(CHUNK_SIZE):
                # UNVERIFIED plaintext: written only to the temp file, not yet trusted.
                writer.write(decryptor.decrypt_chunk(chunk))
            # Verify the tag; an error here means nothing written so far was authenticated.
            writer.write(decryptor.finish())
    except alloy.AlloyError as e:
        os.remove(temp_path)
        raise SystemExit(f"Decryption failed authentication; discarded unverified output: {e}")
    # Authenticated: atomically commit the temp file as the real output.
    os.replace(temp_path, output_path)


async def main():
    tenant_id = os.environ.get("TENANT_ID", "tenant")
    # Note: in practice this must be 32 cryptographically-secure bytes
    key_bytes = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    config = alloy.StandaloneConfiguration(
        alloy.StandardSecrets(1, [alloy.StandaloneSecret(1, alloy.Secret(key_bytes))]),
        {},
        {},
    )
    sdk = alloy.Standalone(config)
    metadata = alloy.AlloyMetadata.new_simple(tenant_id)

    # Create a sample input file if one doesn't exist, so the example is self-contained. In a real
    # program this would be whatever large file you want to protect.
    input_path = "plaintext.bin"
    if not os.path.exists(input_path):
        with open(input_path, "wb") as f:
            f.write(bytes(i % 251 for i in range(5 * 1024 * 1024)))  # 5 MiB

    # Streaming encrypt: plaintext.bin -> plaintext.bin.enc (+ the EDEK in plaintext.bin.edek)
    edek = await encrypt_file(sdk, metadata, input_path, "plaintext.bin.enc")
    with open("plaintext.bin.edek", "wb") as f:
        f.write(edek)
    print("Encrypted plaintext.bin -> plaintext.bin.enc (EDEK stored in plaintext.bin.edek)")

    # Streaming decrypt: plaintext.bin.enc (+ .edek) -> decrypted.bin
    with open("plaintext.bin.edek", "rb") as f:
        stored_edek = f.read()
    await decrypt_file(sdk, metadata, "plaintext.bin.enc", stored_edek, "decrypted.bin")
    print("Decrypted plaintext.bin.enc -> decrypted.bin")

    # Verify the round trip.
    with open(input_path, "rb") as f:
        original = f.read()
    with open("decrypted.bin", "rb") as f:
        decrypted = f.read()
    assert original == decrypted, "Decrypted file did not match the original!"
    print(f"Success: decrypted.bin matches {input_path} ({len(original)} bytes).")


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
