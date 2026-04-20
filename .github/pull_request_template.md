# Pull Request

## Description

Brief description of what this PR does.

Fixes #(issue number)

## Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring
- [ ] Test improvement
- [ ] CI/CD improvement

## Changes Made

Detailed list of changes:

- Changed X in file Y
- Added new detector for Z
- Updated documentation for feature W

## Testing

### How Has This Been Tested?

- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

**Test Configuration**:
- OS: [e.g., Ubuntu 22.04]
- Rust Version: [e.g., 1.75.0]

### Test Results

```bash
# Paste test output here
cargo test --all
```

## Checklist

### Code Quality

- [ ] My code follows the project's style guidelines (ran `cargo fmt`)
- [ ] I have performed a self-review of my code
- [ ] I have commented complex areas of my code
- [ ] My changes generate no new warnings (`cargo clippy -- -D warnings`)
- [ ] I have added/updated documentation (doc comments)

### Testing

- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes (`cargo test`)
- [ ] I have tested with `--verbose` flag for detailed output
- [ ] I have tested the affected commands end-to-end

### Documentation

- [ ] I have updated the README if needed
- [ ] I have updated CHANGELOG.md following [Keep a Changelog](https://keepachangelog.com/)
- [ ] I have updated relevant documentation files (IMPLEMENTATION.md, etc.)
- [ ] I have added/updated doc comments for public APIs

### Error Handling & Logging

- [ ] All errors are properly handled (no unwrap/expect in runtime code)
- [ ] Appropriate log levels used (ERROR for critical, WARN for issues, INFO for progress, DEBUG for details)
- [ ] Error messages include helpful context

### Breaking Changes

If this PR includes breaking changes:

- [ ] I have clearly documented all breaking changes
- [ ] I have updated the version number appropriately
- [ ] I have provided migration guidance

**Breaking Changes**:
- Description of what breaks
- Migration path for users

## Screenshots (if applicable)

For UI or output changes, include before/after screenshots.

### Before
```
[paste terminal output or screenshot]
```

### After
```
[paste terminal output or screenshot]
```

## Performance Impact

Does this PR affect performance?

- [ ] No performance impact
- [ ] Performance improved (include benchmarks)
- [ ] Performance degraded (explain why acceptable)

## Additional Notes

Any additional information, context, or concerns for reviewers.

## Reviewers

@mention specific reviewers if needed

---

**By submitting this pull request, I confirm that my contribution is made under the terms of the Apache 2.0 license.**
