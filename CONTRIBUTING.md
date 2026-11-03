# Contributing to Sentinel PE

Thank you for helping make Windows PE analysis more accessible to defenders, researchers, and incident responders.

## Scope

Sentinel PE is a **defensive, local-first** tool. All contributions must stay within these bounds:

✅ **In scope:**
- Improved PE header parsing (sections, directories, resources)
- New defensive heuristic rules for malware detection
- UI/UX improvements
- Performance optimizations
- Test coverage for existing features
- Documentation and translations

❌ **Out of scope (will not be merged):**
- Code that executes sample files
- Offensive capabilities (exploits, payload generation, C2 features)
- Network scanning or active reconnaissance
- File modification or deletion features
- Code that bypasses OS security controls

## Development Setup

```bash
# Clone and install
git clone https://github.com/whispering3/Sentinel-PE.git
cd Sentinel-PE
npm install

# Start development mode
npm run dev

# Run tests
npm test

# Build for production
npm run build
npm run dist   # generates .exe installer
```

## Adding a New Heuristic Rule

Rules live in `src/lib/findings.ts`. Each rule is a `Rule` object:

```typescript
{
  severity: 'high',          // informational | low | medium | high | critical
  category: 'ransomware',   // ransomware | packer | injection | persistence | evasion | privilege-escalation | network | general
  title: 'Descriptive Rule Title',
  check: (analysis) => {
    // Return a string with evidence if the rule matches,
    // or false if it does not match.
    const found = analysis.importedFunctions.find(f => f.name === 'SomeAPI')
    return found ? `Found: ${found.name} in ${found.dll}` : false
  },
}
```

Rule guidelines:
- Severity must be justified — reserve `critical` for near-certain malicious indicators
- Include evidence that helps an analyst understand *why* it fired
- Add test cases in `src/lib/__tests__/findings.test.ts`

## Submitting a Pull Request

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-improvement`
3. Implement your change with tests
4. Run `npx tsc --noEmit && npm test -- --run`
5. Open a PR against the `main` branch
6. Describe your changes using the PR template

## Reporting Vulnerabilities

See [SECURITY.md](SECURITY.md) for responsible disclosure.
