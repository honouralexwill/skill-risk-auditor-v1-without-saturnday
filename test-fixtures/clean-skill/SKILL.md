---
name: clean-skill
description: A perfectly safe skill that formats JSON files
---

# JSON Formatter

When invoked, read the file at the given path and format it as pretty-printed JSON.

## Steps

1. Read the file using the Read tool
2. Parse it as JSON
3. Format with 2-space indentation
4. Write the result back using the Write tool
