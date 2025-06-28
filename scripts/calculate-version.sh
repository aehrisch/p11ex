#!/bin/bash
set -e

# Install Node.js and npm
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# Install semantic-release
npm install -g semantic-release @semantic-release/commit-analyzer

# Create semantic-release config
cd /app
echo "Current directory: $(pwd)"

# Fix Git ownership issues
git config --global --add safe.directory /app

echo "Git status:"
git status --porcelain || echo "Git not available"
echo "Git log --oneline -5:"
git log --oneline -5 || echo "Git log failed"

cat > .releaserc.json << 'EOF'
{
  "branches": ["main"],
  "plugins": [
    "@semantic-release/commit-analyzer"
  ]
}
EOF

# Run semantic-release in dry-run mode to get next version
npx semantic-release --dry-run --no-ci > /app/semantic-output.txt 2>&1 || true

# Check if semantic-release would create a new release
if grep -q 'The next release version is' /app/semantic-output.txt; then
  VERSION=$(grep 'The next release version is' /app/semantic-output.txt | sed 's/.*The next release version is \(.*\)/\1/')
  echo "New version detected: $VERSION"
  echo "$VERSION" > /app/version.txt
else
  # No conventional commits found, no new release needed
  echo "No conventional commits found. No new release needed."
  echo "NO_RELEASE_NEEDED" > /app/version.txt
fi 
