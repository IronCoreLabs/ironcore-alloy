# API Reference

`AlloyError` documentation is not correctly generated. Its definition is included here manually:

```python
class AlloyError(Exception):
    """
    Errors related to IronCore Alloy SDK
    """
    class InvalidConfiguration(AlloyError):
        """
        Error while loading configuration.
        """
    class InvalidKey(AlloyError):
        """
        Error with user key used
        """
    class InvalidInput(AlloyError):
        """
        Error with user input
        """
    class EncryptError(AlloyError):
        """
        Errors while encrypting 
        """
    class DecryptError(AlloyError):
        """
        Errors while decrypting 
        """
    class DocumentError(AlloyError):
        """
        Error when encrypting or decrypting documents
        """
    class ProtobufError(AlloyError):
        """
        Error when parsing encryption headers/metadata
        """
    class TenantSecurityError(AlloyError):
        """
        Error with requests to TSC
        """
    class IronCoreDocumentsError(AlloyError):
        """
        Error with IronCore Documents
        """
```

Keep in mind that this manual definition may get out of step with the actual source so refer to the source if there is any ambiguity.

::: ironcore_alloy.ironcore_alloy
