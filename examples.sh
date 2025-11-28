#!/bin/bash

# Example Usage Script for Shai-Hulud Scanner
# This demonstrates different ways to use the scanner

echo "======================================"
echo "Shai-Hulud Scanner - Usage Examples"
echo "======================================"
echo ""

# Example 1: Scan current directory
echo "Example 1: Scanning current directory"
echo "Command: node scan-malicious-packages.js ."
echo ""

# Example 2: Scan a specific project folder
echo "Example 2: Scanning a specific project"
echo "Command: node scan-malicious-packages.js /path/to/your/project"
echo ""

# Example 3: Using npm scripts
echo "Example 3: Using npm test"
echo "Command: npm test"
echo ""

# Example 4: Test with malicious packages (demo)
echo "Example 4: Testing with malicious packages (demo folder)"
echo "Command: node scan-malicious-packages.js test-example"
echo ""
node scan-malicious-packages.js test-example

# Example 5: CI/CD Integration
echo ""
echo "Example 5: CI/CD Integration"
echo "In your CI/CD pipeline, you can use:"
echo "  node scan-malicious-packages.js . || exit 1"
echo ""
