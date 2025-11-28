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
  constructor(targetFolder, eventsFolder) {
    this.targetFolder = targetFolder;
    this.eventsFolder = eventsFolder;
    this.maliciousPackages = new Map(); // Map<packageName, Set<versions>>
    this.findings = [];
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
   * Load and parse package.json from target folder
   */
  loadPackageJson() {
    const packageJsonPath = path.join(this.targetFolder, 'package.json');
    
    if (!fs.existsSync(packageJsonPath)) {
      throw new Error(`package.json not found in ${this.targetFolder}`);
    }

    console.log(`${colors.blue}Loading package.json from ${this.targetFolder}...${colors.reset}\n`);
    
    const packageJsonContent = fs.readFileSync(packageJsonPath, 'utf-8');
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
            dependencyType
          });
        }
      }
    }
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

    // Load package.json
    const packageJson = this.loadPackageJson();
    const projectName = packageJson.name || 'Unknown Project';
    console.log(`${colors.cyan}Scanning project: ${colors.bold}${projectName}${colors.reset}\n`);

    // Scan different dependency types
    this.scanDependencies(packageJson.dependencies, 'dependencies');
    this.scanDependencies(packageJson.devDependencies, 'devDependencies');
    this.scanDependencies(packageJson.peerDependencies, 'peerDependencies');
    this.scanDependencies(packageJson.optionalDependencies, 'optionalDependencies');

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
  // Get target folder from command line argument
  const targetFolder = process.argv[2];
  
  if (!targetFolder) {
    console.error(`${colors.red}Error: Please provide a folder path as an argument${colors.reset}`);
    console.log(`\nUsage: node scan-malicious-packages.js <folder-path>`);
    console.log(`Example: node scan-malicious-packages.js /path/to/project\n`);
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
    const scanner = new MaliciousPackageScanner(absoluteTargetPath, eventsFolder);
    await scanner.scan();
  } catch (error) {
    console.error(`${colors.red}${colors.bold}Error: ${error.message}${colors.reset}\n`);
    process.exit(1);
  }
}

// Run the scanner
main();
