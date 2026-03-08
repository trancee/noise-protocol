# JUnit Skill Pack Maintainer Guide

Use this file when updating or extending the JUnit workspace customization pack.

For the standard repository-level entry point, see [../../../CONTRIBUTING.md](../../../CONTRIBUTING.md).

## Package Shape

- The canonical skill lives at [../SKILL.md](../SKILL.md).
- Focused slash-command entry points live under [../../prompts/](../../prompts/).
- Reusable starter snippets live under [../assets/](../assets/).
- Routing and support docs live under [./](./).
- Repository maintenance scripts live under [../../../scripts/](../../../scripts/).
- Workspace editor recommendations live in [../../../.vscode/extensions.json](../../../.vscode/extensions.json).
- Workspace editor defaults live in [../../../.vscode/settings.json](../../../.vscode/settings.json).

## Extension Rules

When adding a new prompt:

1. Create the prompt under [../../prompts/](../../prompts/).
2. Link it from [../../prompts/README.md](../../prompts/README.md).
3. Add it to [../README.md](../README.md) and [../../../README.md](../../../README.md) if it is a first-class workflow.
4. Add an example to [examples-catalog.md](./examples-catalog.md) when the prompt maps to a common task.

When adding a new starter asset:

1. Store Java snippets as `.java.txt`, not `.java`.
2. Link the asset from [../SKILL.md](../SKILL.md) and [../README.md](../README.md).
3. Add it to [examples-catalog.md](./examples-catalog.md) if it helps route users to the right starter.

When adding new guidance:

1. Prefer short routing docs over bloating the main skill.
2. Keep the skill focused on decision rules and workflow.
3. Put high-frequency routing help in [junit-reference-map.md](./junit-reference-map.md) or [examples-catalog.md](./examples-catalog.md).

## Validation Checklist

- Run editor validation on any changed markdown or prompt files.
- Keep prompt names and slash-command examples consistent across docs.
- Preserve the `.java.txt` convention for starter snippets.
- Follow [../../../.editorconfig](../../../.editorconfig) for line endings, final newlines, and indentation.
- Rely on [../../../.gitattributes](../../../.gitattributes) to keep repository text files normalized to LF.
- Run [../../../scripts/audit-skill-pack.sh](../../../scripts/audit-skill-pack.sh) for a repeatable repo-level hygiene check.
- In VS Code, you can run the `Audit Skill Pack` task from [../../../.vscode/tasks.json](../../../.vscode/tasks.json).
- Update repo memory if the package surface changes materially.

## Release Checklist

Before considering a pack update complete:

1. Confirm the changed prompt or asset is listed everywhere it should be:
	- [../../prompts/README.md](../../prompts/README.md)
	- [../README.md](../README.md)
	- [../../../README.md](../../../README.md) when it is a first-class workflow
2. Confirm routing docs still point to the right place:
	- [junit-reference-map.md](./junit-reference-map.md) for topic routing
	- [examples-catalog.md](./examples-catalog.md) for task-to-prompt routing
3. Confirm [../SKILL.md](../SKILL.md) reflects any new bundled asset or routing guidance.
4. Run editor validation on every changed file.
5. Update repo memory if the package surface, conventions, or routing docs changed.

## Non-Goals

- Do not turn this repo into a buildable Java project just to host examples.
- Do not add compiled sample code or dependency-managed test sources.
- Do not leave new prompts undocumented in the prompt catalog or README files.
