# API Reference

`CloakedAiError` documentation is not correctly generated. Its definition is included here manually:

```python
class CloakedAiError(Exception):
    """
    Errors related to CloakedAiStandalone
    """
    class InvalidConfiguration(CloakedAiError):
        """
        Error while loading configuration.
        """
    class InvalidKey(CloakedAiError):
        """
        Error with key used to initialize CloakedAiStandalone
        """
    class InvalidIv(CloakedAiError):
        """
        Error during decryption with provided IV
        """
    class InvalidAuthHash(CloakedAiError):
        """
        Error during decryption with provided authentication hash
        """
    class InvalidInput(CloakedAiError):
        """
        Error with input vector. Likely due to overflow with large values
        """
    class DocumentError(CloakedAiError):
        """
        Error when encrypting or decrypting documents
        """
    class ProtobufError(CloakedAiError):
        """
        Error when parsing encryption headers/metadata
        """
    class TenantSecurityError(CloakedAiError):
        """
        Error with requests to TSC
        """
    class IronCoreDocumentsError(CloakedAiError):
        """
        Error with IronCore Documents
        """
```

Keep in mind that this manual definition may get out of step with the actual source, and refer to the source if there is any ambiguity.

::: cloaked_ai.cloaked_ai
