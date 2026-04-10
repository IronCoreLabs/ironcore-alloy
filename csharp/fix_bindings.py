#!/usr/bin/env python3
"""Post-process generated uniffi C# bindings to fix known codegen issues.

Issues fixed:
1. Chained `using` aliases that reference other aliases (CS0246)
2. Record properties with the same name as their enclosing type (CS0542)
"""

import re
import sys
from pathlib import Path


def resolve_using_aliases(content: str) -> str:
    """Expand chained using aliases so each alias references only real types."""
    # Parse all using aliases
    alias_pattern = re.compile(r"^using\s+(\w+)\s*=\s*(.+);$", re.MULTILINE)
    aliases: dict[str, str] = {}
    for m in alias_pattern.finditer(content):
        aliases[m.group(1)] = m.group(2).strip()

    # Iteratively resolve chains until stable
    changed = True
    while changed:
        changed = False
        for name, target in list(aliases.items()):
            new_target = target
            for alias_name, alias_target in aliases.items():
                if alias_name == name:
                    continue
                # Replace whole-word occurrences of alias_name in target
                new_target = re.sub(
                    rf"\b{re.escape(alias_name)}\b", alias_target, new_target
                )
            if new_target != target:
                aliases[name] = new_target
                changed = True

    # Replace the using lines in the content
    def replace_alias(m: re.Match) -> str:
        name = m.group(1)
        if name in aliases:
            return f"using {name} = {aliases[name]};"
        return m.group(0)

    return alias_pattern.sub(replace_alias, content)


def fix_record_property_names(content: str) -> str:
    """Rename record properties that clash with their enclosing type name."""
    # Find records where a positional parameter has the same name as the record
    # Pattern: `record Foo (\n    SomeType Foo,` or `record Foo (\n    type[] Foo,`
    record_pattern = re.compile(
        r"internal record (\w+)\s*\(([^)]+)\)", re.DOTALL
    )

    renames: dict[str, str] = {}  # "RecordName.Property" -> "NewProperty"

    for m in record_pattern.finditer(content):
        record_name = m.group(1)
        params_block = m.group(2)
        # Check if any parameter name matches the record name
        param_pattern = re.compile(rf"\b(\S+)\s+{re.escape(record_name)}\b")
        if param_pattern.search(params_block):
            renames[record_name] = f"{record_name}Value"

    # Apply renames
    for old_name, new_name in renames.items():
        # In record parameter list: `Type OldName,` or `Type OldName\n)`
        content = re.sub(
            rf"(\S+(?:\[\])?)\s+{re.escape(old_name)}(\s*[,)])",
            rf"\1 {new_name}\2",
            content,
        )
        # Named parameter in constructor calls: `OldName:`
        content = re.sub(
            rf"\b{re.escape(old_name)}:", f"{new_name}:", content
        )
        # Property access: `value.OldName` or `.OldName)`
        content = re.sub(
            rf"(\.){re.escape(old_name)}\b", rf"\g<1>{new_name}", content
        )

    return content


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file.cs>", file=sys.stderr)
        sys.exit(1)

    path = Path(sys.argv[1])
    content = path.read_text()
    content = resolve_using_aliases(content)
    content = fix_record_property_names(content)
    path.write_text(content)
    print(f"Fixed {path}")


if __name__ == "__main__":
    main()
