# C# build and publish info

## Requirements

- .NET 9.0+
- Python 3 (for `fix_bindings.py` post-processing)

## Build

Ensure the library and source have been created, typically done by running `cargo t` in `../`. The environment requirements for that are in the top level README or the `flake.nix`.

The generated `ironcore_alloy.cs` bindings require post-processing to fix known uniffi C# codegen issues with our library:

```console
python3 fix_bindings.py ironcore_alloy.cs
```

This script fixes two issues:
1. **Chained `using` aliases** that reference other aliases (CS0246) — expanded so each alias references only concrete types.
2. **Record property name collisions** (CS0542) — when a record has a positional property with the same name as the record type, the property is renamed with a `Value` suffix.

### API differences from post-processing

Due to fix #2, some record properties differ from what the Alloy documentation shows. The affected properties are:

| Record             | Documented property  | C# property            |
|--------------------|----------------------|------------------------|
| `PlaintextVector`  | `PlaintextVector`    | `PlaintextVectorValue` |
| `EncryptedVector`  | `EncryptedVector`    | `EncryptedVectorValue` |
| `PlaintextField`   | `PlaintextField`     | `PlaintextFieldValue`  |
| `EncryptedField`   | `EncryptedField`     | `EncryptedFieldValue`  |

## Usage

Since the C# bindings are not yet published as a NuGet package, you need to include the generated source directly in your project:

1. Build the native library and generate bindings (see [Build](#build) above).
2. Run `python3 fix_bindings.py ironcore_alloy.cs` to post-process the generated file.
3. Copy `ironcore_alloy.cs` and the native library (`libironcore_alloy.dylib` on macOS, `libironcore_alloy.so` on Linux, `ironcore_alloy.dll` on Windows) into your project.
4. Add the source file to your project and ensure the native library is in your application's runtime directory.
5. Your project must target .NET 9.0 or later.

A minimal `.csproj` might look like:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net9.0</TargetFramework>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
  </PropertyGroup>
</Project>
```

Note: `AllowUnsafeBlocks` is required because the generated bindings use `unsafe` code for native interop.

## Testing

```console
dotnet test
```

### Integration tests

The `IntegrationSdkUnknownTenant` test is skipped by default because it requires a Tenant Security Proxy (TSP) running at `http://localhost:32804`. To run it:

1. Start the TSP from the repo root: `docker compose -f tests/docker-compose.yml up`
2. Remove the `Skip` parameter from the `[Fact]` attribute in `IroncoreAlloyTest.cs`
3. Run `dotnet test`

## Publishing

TODO — NuGet publishing is not yet set up.
