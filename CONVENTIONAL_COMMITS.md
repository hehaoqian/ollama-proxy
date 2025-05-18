# Conventional Commits Guide

This project follows [Conventional Commits](https://www.conventionalcommits.org/) to make the commit history easy to read and automatically generate changelogs.

## Commit Message Format

Each commit message consists of a **header**, an optional **body**, and an optional **footer**:

```
<type>(<optional scope>): <description>

<optional body>

<optional footer>
```

## Types

- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation only changes
- `style`: Changes that do not affect the meaning of the code (white-space, formatting, etc)
- `refactor`: A code change that neither fixes a bug nor adds a feature
- `perf`: A code change that improves performance
- `test`: Adding missing tests or correcting existing tests
- `build`: Changes that affect the build system or external dependencies
- `ci`: Changes to our CI configuration files and scripts
- `chore`: Other changes that don't modify src or test files
- `revert`: Reverts a previous commit

## Examples

### New Feature
```
feat(api): add ability to parse request headers
```

### Bug Fix
```
fix(db): prevent SQL injection in query params
```

### Documentation Update
```
docs(readme): update installation instructions
```

### Breaking Change
```
feat(api)!: change authentication protocol

BREAKING CHANGE: The authentication protocol has been changed to OAuth2.
Previous authentication methods will no longer work.
```

## Scopes

The scope should be the name of the component affected:

- `api`
- `auth`
- `log`
- `db`
- `proxy`
- `config`
- `cli`
- `docs`
- `test`
- etc.

## Tools

You can use tools like [Commitizen](https://github.com/commitizen/cz-cli) to help format your commit messages according to this convention.
