# Shai-Hulud Malicious Package Scanner 

A Node.js tool to scan `package.json` files for known malicious npm packages using CSV data sources.

## Overview

This scanner checks your project's dependencies against a database of known malicious packages stored in CSV files. It supports semver version matching to detect both exact and range-based version matches.

## Features

- ✅ Scans all dependency types (dependencies, devDependencies, peerDependencies, optionalDependencies)
- ✅ **Recursive scanning** - scan all package.json files in subdirectories
- ✅ Supports multiple CSV files in the `/events` folder
- ✅ Intelligent version matching using semver
- ✅ Color-coded terminal output
- ✅ Detailed reporting of findings
- ✅ Exit codes for CI/CD integration

## Installation

1. Clone or download this repository
2. Install dependencies:

```bash
npm install
```

## Usage

### Basic Usage

Scan a specific folder:

```bash
node scan-malicious-packages.js /path/to/your/project
```

### Recursive Scanning

Scan a folder and all its subdirectories for package.json files (useful for monorepos):

```bash
node scan-malicious-packages.js -r /path/to/your/monorepo
# or
node scan-malicious-packages.js --recursive /path/to/your/monorepo
```

This will:
- Find all `package.json` files in the target directory and subdirectories
- Skip `node_modules` and hidden directories
- Scan each found `package.json` file independently
- Report which file contains any malicious packages

### Using npm scripts

Scan the current directory:

```bash
npm test
```

Custom scan:

```bash
npm run scan /path/to/your/project
```

Recursive scan:

```bash
npm run scan -- -r /path/to/your/monorepo
```

### As a global command (after npm link)

```bash
npm link
shai-hulud /path/to/your/project
shai-hulud -r /path/to/your/monorepo
```

## CSV Format

The scanner expects CSV files in the `/events` folder with the following format:

```csv
Package Name,Version
package-name,1.0.0
@scoped/package,2.5.3
```

### Supported CSV Column Names

- `Package Name` or `package` or `name`
- `Version` or `version`

## Output

### Clean Scan
```
✓ SCAN COMPLETE - NO MALICIOUS PACKAGES DETECTED
All dependencies are clean!
```

### Malicious Packages Found
```
⚠ WARNING: MALICIOUS PACKAGES DETECTED

Found 2 malicious package(s):

1. suspicious-package
   Installed version: ^1.2.3
   Malicious version: 1.2.3
   Match type: exact
   Dependency type: dependencies

2. @scoped/bad-package
   Installed version: ~2.0.0
   Malicious version: 2.0.1
   Match type: range
   Dependency type: devDependencies
```

## Exit Codes

- `0`: No malicious packages found
- `1`: Malicious packages detected or error occurred

## Version Matching

The scanner uses semver to intelligently match versions:

- **Exact match**: `1.2.3` matches `1.2.3`
- **Range match**: `^1.2.0` can match malicious version `1.2.3`
- Handles common prefixes: `^`, `~`, `>=`, `<=`, etc.

## CI/CD Integration

Use the exit code to fail builds when malicious packages are detected:

```bash
#!/bin/bash
node scan-malicious-packages.js . || exit 1
```

## Requirements

- Node.js 12.x or higher
- npm or yarn

## Dependencies

- [papaparse](https://www.npmjs.com/package/papaparse) - CSV parsing
- [semver](https://www.npmjs.com/package/semver) - Semantic versioning

## License

MIT
