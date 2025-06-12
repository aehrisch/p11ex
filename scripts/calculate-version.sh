#!/bin/bash
set -e

# Install Node.js and npm
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# Install semantic-release
npm install -g semantic-release @semantic-release/changelog @semantic-release/git

# Create semantic-release config
cat > .releaserc.json << 'EOF'
{
  "branches": ["main"],
  "plugins": [
    "@semantic-release/commit-analyzer",
    "@semantic-release/release-notes-generator",
    "@semantic-release/changelog",
    "@semantic-release/npm",
    "@semantic-release/git"
  ]
}
EOF

# Run semantic-release in dry-run mode to get next version
npx semantic-release --dry-run --no-ci > /tmp/semantic-output.txt 2>&1 || true

# Extract version from output
if grep -q 'The next release version is' /tmp/semantic-output.txt; then
  VERSION=$(grep 'The next release version is' /tmp/semantic-output.txt | sed 's/.*The next release version is \(.*\)/\1/')
else
  # If no conventional commits, use current version from mix.exs
  VERSION=$(grep 'version:' mix.exs | sed 's/.*version: "\(.*\)".*/\1/')
fi

if [ -z "$VERSION" ]; then
  echo "ERROR: Could not determine version."
  exit 1
fi

echo "$VERSION" > /app/version.txt 
