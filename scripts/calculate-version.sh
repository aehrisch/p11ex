#!/bin/bash
set -e

# Change to the app directory
cd /app
echo "Current directory: $(pwd)"

# Fix Git ownership issues
git config --global --add safe.directory /app

echo "Git status:"
git status --porcelain || echo "Git not available"
echo "Git log --oneline -5:"
git log --oneline -5 || echo "Git log failed"

# Get the latest tag
LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
echo "Latest tag: $LATEST_TAG"

# Extract version from tag (remove 'v' prefix)
CURRENT_VERSION=$(echo $LATEST_TAG | sed 's/^v//')
echo "Current version: $CURRENT_VERSION"

# Get commits since the latest tag
COMMITS_SINCE_TAG=$(git log --oneline --no-merges ${LATEST_TAG}..HEAD 2>/dev/null || git log --oneline --no-merges HEAD~10..HEAD)

echo "Commits since $LATEST_TAG:"
echo "$COMMITS_SINCE_TAG"

# Analyze conventional commits
MAJOR_BUMP=false
MINOR_BUMP=false
PATCH_BUMP=false

while IFS= read -r commit; do
    if [[ -z "$commit" ]]; then
        continue
    fi
    
    # Extract commit message (everything after the hash)
    MESSAGE=$(echo "$commit" | sed 's/^[a-f0-9]* //')
    
    echo "Analyzing commit: $MESSAGE"
    
    # Check for breaking changes
    if [[ "$MESSAGE" =~ BREAKING\ CHANGE ]] || [[ "$MESSAGE" =~ ^[^:]+!: ]]; then
        echo "  -> BREAKING CHANGE detected"
        MAJOR_BUMP=true
    # Check for features
    elif [[ "$MESSAGE" =~ ^feat: ]] || [[ "$MESSAGE" =~ ^feat\( ]]; then
        echo "  -> Feature detected"
        MINOR_BUMP=true
    # Check for fixes
    elif [[ "$MESSAGE" =~ ^fix: ]] || [[ "$MESSAGE" =~ ^fix\( ]]; then
        echo "  -> Fix detected"
        PATCH_BUMP=true
    # Check for other conventional commit types that might indicate changes
    elif [[ "$MESSAGE" =~ ^(docs|style|refactor|perf|test|chore): ]] || [[ "$MESSAGE" =~ ^(docs|style|refactor|perf|test|chore)\( ]]; then
        echo "  -> Other change detected"
        PATCH_BUMP=true
    fi
done <<< "$COMMITS_SINCE_TAG"

# Calculate next version
if [[ "$CURRENT_VERSION" == "0.0.0" ]]; then
    # If no previous version, start with 0.1.0
    NEXT_VERSION="0.1.0"
elif [[ "$MAJOR_BUMP" == "true" ]]; then
    # Major version bump
    MAJOR=$(echo $CURRENT_VERSION | cut -d. -f1)
    NEW_MAJOR=$((MAJOR + 1))
    NEXT_VERSION="${NEW_MAJOR}.0.0"
elif [[ "$MINOR_BUMP" == "true" ]]; then
    # Minor version bump
    MAJOR=$(echo $CURRENT_VERSION | cut -d. -f1)
    MINOR=$(echo $CURRENT_VERSION | cut -d. -f2)
    NEW_MINOR=$((MINOR + 1))
    NEXT_VERSION="${MAJOR}.${NEW_MINOR}.0"
elif [[ "$PATCH_BUMP" == "true" ]]; then
    # Patch version bump
    MAJOR=$(echo $CURRENT_VERSION | cut -d. -f1)
    MINOR=$(echo $CURRENT_VERSION | cut -d. -f2)
    PATCH=$(echo $CURRENT_VERSION | cut -d. -f3)
    NEW_PATCH=$((PATCH + 1))
    NEXT_VERSION="${MAJOR}.${MINOR}.${NEW_PATCH}"
else
    # No conventional commits found
    echo "No conventional commits found. No new release needed."
    echo "NO_RELEASE_NEEDED" > /app/version.txt
    exit 0
fi

echo "Next version: $NEXT_VERSION"
echo "$NEXT_VERSION" > /app/version.txt

# Create semantic-output.txt for debugging
cat > /app/semantic-output.txt << EOF
Custom conventional commit analysis:
Current version: $CURRENT_VERSION
Next version: $NEXT_VERSION
Commits analyzed: $(echo "$COMMITS_SINCE_TAG" | wc -l)
Major bump: $MAJOR_BUMP
Minor bump: $MINOR_BUMP
Patch bump: $PATCH_BUMP

Commits since $LATEST_TAG:
$COMMITS_SINCE_TAG
EOF 
