import ironcore_alloy as alloy
import os
import asyncio
import json


async def main():
    tenant_id = os.environ.get("TENANT_ID", "tenant-gcp")
    api_key = os.environ.get("API_KEY", "0WUaXesNgbTAuLwn")
    tsp_uri = "http://localhost:32804"
    approximation_factor = 7.2
    config = alloy.SaasShieldConfiguration(
        tsp_uri, api_key, False, approximation_factor
    )
    sdk = alloy.SaasShield(config)

    jim_original = json.dumps(
        {
            "name": "Jim Bridger",
            "address": "2825-519 Stone Creek Rd, Bozeman, MT 59715",
            "ssn": "000-12-2345",
        }
    )
    metadata = alloy.AlloyMetadata.new_simple(tenant_id)
    # Encrypt Jim's personal information
    encrypted = await sdk.standard().encrypt(
        {"jim": bytes(jim_original, "utf-8")}, metadata
    )
    # Store off the `document` and `edek`

    # -----------------------------

    # Later, retrieve the `document` and `edek`
    encrypted_recreated = alloy.EncryptedDocument(
        edek=encrypted.edek, document=encrypted.document
    )
    # Decrypt Jim's personal information
    decrypted = await sdk.standard().decrypt(encrypted_recreated, metadata)
    jim_decrypted = json.loads(decrypted["jim"])

    print("Decrypted SSN: ", jim_decrypted["ssn"])
    print("Decrypted address: ", jim_decrypted["address"])
    print("Decrypted name: ", jim_decrypted["name"])


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
