#!/usr/bin/env node

/**
 * Shai-Hulud Malicious Package Scanner
 * Scans package.json for malicious packages using CSV data from /events folder
 */

const fs = require('fs');
const path = require('path');
const Papa = require('papaparse');
const semver = require('semver');

// ANSI color codes for terminal output
const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    bold: '\x1b[1m'
};

class MaliciousPackageScanner {
    constructor(targetFolder, eventsFolder, recursive = false) {
        this.targetFolder = targetFolder;
        this.eventsFolder = eventsFolder;
        this.recursive = recursive;
        this.maliciousPackages = new Map(); // Map<packageName, Set<versions>>
        this.findings = [];
        this.currentScanPath = null; // Track which package.json is currently being scanned
    }

    /**
     * Load all CSV files from the events folder
     */
    async loadMaliciousPackages() {
        console.log(`${colors.blue}Loading malicious package data from ${this.eventsFolder}...${colors.reset}\n`);

        const files = fs.readdirSync(this.eventsFolder);
        const csvFiles = files.filter(file => file.endsWith('.csv'));

        if (csvFiles.length === 0) {
            throw new Error(`No CSV files found in ${this.eventsFolder}`);
        }

        for (const csvFile of csvFiles) {
            const filePath = path.join(this.eventsFolder, csvFile);
            await this.parseCsvFile(filePath, csvFile);
        }

        console.log(`${colors.green}✓ Loaded ${this.maliciousPackages.size} unique malicious packages${colors.reset}\n`);
    }

    /**
     * Parse a single CSV file
     */
    async parseCsvFile(filePath, fileName) {
        const csvContent = fs.readFileSync(filePath, 'utf-8');

        return new Promise((resolve, reject) => {
            Papa.parse(csvContent, {
                header: true,
                skipEmptyLines: true,
                complete: (results) => {
                    console.log(`  - Processing ${fileName}: ${results.data.length} entries`);

                    results.data.forEach(row => {
                        // Handle various CSV column name formats
                        const packageName = row['Package Name'] || row['package'] || row['name'];
                        const version = row['Version'] || row['version'];

                        if (packageName && version) {
                            if (!this.maliciousPackages.has(packageName)) {
                                this.maliciousPackages.set(packageName, new Set());
                            }
                            this.maliciousPackages.get(packageName).add(version.trim());
                        }
                    });

                    resolve();
                },
                error: (error) => {
                    reject(new Error(`Failed to parse ${fileName}: ${error.message}`));
                }
            });
        });
    }

    /**
   * Recursively find all package.json files in a directory
   */
    findPackageJsonFiles(dir, fileList = []) {
        try {
            const files = fs.readdirSync(dir);

            for (const file of files) {
                const filePath = path.join(dir, file);

                try {
                    const stat = fs.statSync(filePath);

                    if (stat.isDirectory()) {
                        // Skip node_modules and hidden directories
                        if (file !== 'node_modules' && !file.startsWith('.')) {
                            this.findPackageJsonFiles(filePath, fileList);
                        }
                    } else if (file === 'package.json') {
                        fileList.push(filePath);
                    }
                } catch (err) {
                    // Skip files we can't access (broken symlinks, socket files, permission issues, etc.)
                    // This is expected when scanning system directories or projects with broken symlinks
                    continue;
                }
            }
        } catch (err) {
            // Skip directories we can't read (permission issues, etc.)
            // Silently continue to next directory
        }

        return fileList;
    }

    /**
     * Load and parse package.json from a specific path
     */
    loadPackageJson(packageJsonPath = null) {
        const targetPath = packageJsonPath || path.join(this.targetFolder, 'package.json');

        if (!fs.existsSync(targetPath)) {
            throw new Error(`package.json not found at ${targetPath}`);
        }

        console.log(`${colors.blue}Loading package.json from ${path.dirname(targetPath)}...${colors.reset}\n`);

        const packageJsonContent = fs.readFileSync(targetPath, 'utf-8');
        return JSON.parse(packageJsonContent);
    }

    /**
     * Check if a version matches a malicious version
     * Handles exact matches and semver ranges
     */
    isVersionMalicious(installedVersion, maliciousVersions) {
        // Remove common prefixes like ^, ~, >=, etc.
        const cleanVersion = installedVersion.replace(/^[^0-9]+/, '');

        for (const maliciousVersion of maliciousVersions) {
            // Exact match
            if (maliciousVersion === cleanVersion || maliciousVersion === installedVersion) {
                return { match: true, type: 'exact', version: maliciousVersion };
            }

            // Check if installed version range satisfies malicious version
            try {
                if (semver.valid(maliciousVersion) && semver.satisfies(maliciousVersion, installedVersion)) {
                    return { match: true, type: 'range', version: maliciousVersion };
                }

                // Check if malicious version satisfies installed range
                if (semver.valid(cleanVersion) && semver.satisfies(cleanVersion, maliciousVersion)) {
                    return { match: true, type: 'range', version: maliciousVersion };
                }
            } catch (e) {
                // Ignore semver parsing errors, continue checking
            }
        }

        return { match: false };
    }

    /**
     * Scan dependencies for malicious packages
     */
    scanDependencies(dependencies, dependencyType) {
        if (!dependencies) return;

        const dependencyCount = Object.keys(dependencies).length;
        console.log(`  Scanning ${dependencyCount} ${dependencyType}...`);


        for (const [packageName, version] of Object.entries(dependencies)) {
            if (this.maliciousPackages.has(packageName)) {
                const maliciousVersions = this.maliciousPackages.get(packageName);
                const versionCheck = this.isVersionMalicious(version, maliciousVersions);

                if (versionCheck.match) {
                    this.findings.push({
                        packageName,
                        installedVersion: version,
                        maliciousVersion: versionCheck.version,
                        matchType: versionCheck.type,
                        dependencyType,
                        packageJsonPath: this.currentScanPath // Add the path to the finding
                    });
                }
            }
        }
    }

    /**
     * Scan a single package.json file
     */
    scanSinglePackageJson(packageJsonPath) {
        const packageJson = this.loadPackageJson(packageJsonPath);
        const projectName = packageJson.name || 'Unknown Project';
        const displayPath = path.relative(this.targetFolder, packageJsonPath) || packageJsonPath;

        console.log(`${colors.cyan}Scanning: ${colors.bold}${displayPath}${colors.reset} (${projectName})\n`);
        this.currentScanPath = packageJsonPath;

        // Scan different dependency types
        this.scanDependencies(packageJson.dependencies, 'dependencies');
        this.scanDependencies(packageJson.devDependencies, 'devDependencies');
        this.scanDependencies(packageJson.peerDependencies, 'peerDependencies');
        this.scanDependencies(packageJson.optionalDependencies, 'optionalDependencies');
    }


    /**
     * Perform the scan
     */
    async scan() {
        console.log(`${colors.bold}${colors.magenta}╔════════════════════════════════════════════════╗${colors.reset}`);
        console.log(`${colors.bold}${colors.magenta}║   Shai-Hulud Malicious Package Scanner       ║${colors.reset}`);
        console.log(`${colors.bold}${colors.magenta}╚════════════════════════════════════════════════╝${colors.reset}\n`);

        // Load malicious package data
        await this.loadMaliciousPackages();

        if (this.recursive) {
            // Recursive mode: find all package.json files
            console.log(`${colors.yellow}Recursive mode enabled. Scanning for all package.json files...${colors.reset}\n`);
            const packageJsonFiles = this.findPackageJsonFiles(this.targetFolder);

            if (packageJsonFiles.length === 0) {
                console.log(`${colors.red}No package.json files found in ${this.targetFolder}${colors.reset}\n`);
                process.exit(0);
            }

            console.log(`${colors.green}Found ${packageJsonFiles.length} package.json file(s)${colors.reset}\n`);
            console.log('═'.repeat(80) + '\n');

            // Scan each package.json file
            packageJsonFiles.forEach((packageJsonPath, index) => {
                if (index > 0) {
                    console.log('\n' + '─'.repeat(80) + '\n');
                }
                this.scanSinglePackageJson(packageJsonPath);
            });
        } else {
            // Single mode: scan the package.json in the target folder
            const packageJsonPath = path.join(this.targetFolder, 'package.json');
            this.scanSinglePackageJson(packageJsonPath);
        }

        // Display results
        this.displayResults();
    }

    /**
     * Display scan results
     */
    displayResults() {
        console.log('\n' + '═'.repeat(80) + '\n');

        if (this.findings.length === 0) {
            console.log(`${colors.green}${colors.bold}✓ SCAN COMPLETE - NO MALICIOUS PACKAGES DETECTED${colors.reset}\n`);
            console.log(`${colors.green}All dependencies are clean!${colors.reset}\n`);
        } else {
            console.log(`${colors.red}${colors.bold}⚠ WARNING: MALICIOUS PACKAGES DETECTED${colors.reset}\n`);
            console.log(`${colors.red}Found ${this.findings.length} malicious package(s):${colors.reset}\n`);

            this.findings.forEach((finding, index) => {
                console.log(`${colors.yellow}${index + 1}. ${colors.bold}${finding.packageName}${colors.reset}`);

                // Show file location in recursive mode
                if (this.recursive && finding.packageJsonPath) {
                    const displayPath = path.relative(this.targetFolder, finding.packageJsonPath);
                    console.log(`   ${colors.cyan}Found in:${colors.reset} ${displayPath}`);
                }

                console.log(`   ${colors.red}Installed version:${colors.reset} ${finding.installedVersion}`);
                console.log(`   ${colors.red}Malicious version:${colors.reset} ${finding.maliciousVersion}`);
                console.log(`   ${colors.red}Match type:${colors.reset} ${finding.matchType}`);
                console.log(`   ${colors.red}Dependency type:${colors.reset} ${finding.dependencyType}`);
                console.log('');
            });

            console.log(`${colors.red}${colors.bold}ACTION REQUIRED:${colors.reset}`);
            console.log(`${colors.yellow}Please review and remove these malicious packages immediately!${colors.reset}\n`);
        }

        // Exit with appropriate code
        process.exit(this.findings.length > 0 ? 1 : 0);
    }
}

/**
 * Main execution
 */
async function main() {
    // Parse command line arguments
    const args = process.argv.slice(2);
    let targetFolder = null;
    let recursive = false;

    // Parse arguments
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '-r' || args[i] === '--recursive') {
            recursive = true;
        } else if (!args[i].startsWith('-')) {
            targetFolder = args[i];
        }
    }

    if (!targetFolder) {
        console.error(`${colors.red}Error: Please provide a folder path as an argument${colors.reset}`);
        console.log(`\nUsage: node scan-malicious-packages.js [options] <folder-path>`);
        console.log(`Options:`);
        console.log(`  -r, --recursive    Recursively scan all package.json files in subdirectories`);
        console.log(`\nExamples:`);
        console.log(`  node scan-malicious-packages.js /path/to/project`);
        console.log(`  node scan-malicious-packages.js -r /path/to/monorepo\n`);
        process.exit(1);
    }

    // Resolve absolute path
    const absoluteTargetPath = path.resolve(targetFolder);

    // Check if folder exists
    if (!fs.existsSync(absoluteTargetPath)) {
        console.error(`${colors.red}Error: Folder not found: ${absoluteTargetPath}${colors.reset}\n`);
        process.exit(1);
    }

    // Events folder is in the same directory as this script
    const eventsFolder = path.join(__dirname, 'events');

    if (!fs.existsSync(eventsFolder)) {
        console.error(`${colors.red}Error: Events folder not found: ${eventsFolder}${colors.reset}\n`);
        process.exit(1);
    }

    try {
        const scanner = new MaliciousPackageScanner(absoluteTargetPath, eventsFolder, recursive);
        await scanner.scan();
    } catch (error) {
        console.error(`${colors.red}${colors.bold}Error: ${error.message}${colors.reset}\n`);
        process.exit(1);
    }
}

// Run the scanner
main();
