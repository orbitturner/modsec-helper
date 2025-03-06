#!/bin/bash

# ==========================
# BUILD & RELEASE SCRIPT
# ==========================
# 🚀 Compiles the Python script into a standalone binary using PyInstaller
# 🏷️ Versioning and publishing to GitHub Releases
# 📢 Author: orbitturner
# ==========================

set -e  # Exit immediately if a command fails

# 🛠️ Configurations
REPO_OWNER="orbitturner"
REPO_NAME="sysadmin-scripts"
PROJECT_DIR="./"
BIN_NAME="install_modsec"
BUILD_DIR="./bin"
GITHUB_API="https://api.github.com/repos/$REPO_OWNER/$REPO_NAME"
GITHUB_RELEASES="https://github.com/$REPO_OWNER/$REPO_NAME/releases/latest/download/$BIN_NAME"

# 🔍 Checking dependencies
echo "🔎 Checking dependencies..."
if ! command -v pyinstaller &>/dev/null; then
    echo "❌ PyInstaller is not installed!"
    echo "➡️  Install it using: pip install pyinstaller"
    exit 1
fi
if ! command -v jq &>/dev/null; then
    echo "❌ jq is not installed (required for version handling)."
    echo "➡️  Install it using: sudo apt install jq"
    exit 1
fi
if ! command -v gh &>/dev/null; then
    echo "❌ GitHub CLI (gh) is not installed."
    echo "➡️  Install it from: https://cli.github.com/"
    exit 1
fi

# 🔥 Navigate to the correct directory
cd "$(dirname "$0")"

# 🔄 Fetch the latest version published on GitHub
echo "🔍 Retrieving the latest version..."
LATEST_VERSION=$(curl -s "$GITHUB_API/releases/latest" | jq -r .tag_name)

# If no version exists, start at v1.0.0
if [[ "$LATEST_VERSION" == "null" || -z "$LATEST_VERSION" ]]; then
    NEW_VERSION="v1.0.0"
else
    # 📈 Auto-increment version (e.g., v1.0.0 → v1.0.1)
    VERSION_PARTS=(${LATEST_VERSION//./ })
    PATCH=$((VERSION_PARTS[2] + 1))
    NEW_VERSION="v${VERSION_PARTS[0]}.${VERSION_PARTS[1]}.$PATCH"
fi

echo "🆕 New version: $NEW_VERSION"

# 🚀 Compile with PyInstaller
echo "⚙️  Compiling the binary..."
pyinstaller --onefile --distpath $BUILD_DIR "$PROJECT_DIR/install_modsec.py"

# 📌 Verify if the build was successful
if [[ ! -f "$BUILD_DIR/$BIN_NAME" ]]; then
    echo "❌ Error: The binary was not generated correctly."
    exit 1
fi
chmod +x "$BUILD_DIR/$BIN_NAME"

# 🏷️ Check if the tag already exists before creating it
if git rev-parse "$NEW_VERSION" >/dev/null 2>&1; then
    echo "⚠️ Git tag $NEW_VERSION already exists. Skipping tag creation."
else
    echo "🏷️ Creating Git tag: $NEW_VERSION"
    git tag -a "$NEW_VERSION" -m "Release $NEW_VERSION - ModSecurity Installer"
    git push origin "$NEW_VERSION"
fi

# 🚀 Check if the release exists before creating it
if gh release view "$NEW_VERSION" >/dev/null 2>&1; then
    echo "⚠️ GitHub release $NEW_VERSION already exists. Skipping release creation."
else
    echo "📦 Creating GitHub release..."
    gh release create "$NEW_VERSION" "$BUILD_DIR/$BIN_NAME" --title "Release $NEW_VERSION" --notes "🚀 New version of install_modsec"
fi

# 📢 Display the download link
echo "✅ Build & release completed successfully!"
echo "📥 You can download the binary using:"
echo "curl -sL $GITHUB_RELEASES -o $BIN_NAME && chmod +x $BIN_NAME && ./$BIN_NAME"
echo "wget -qO $BIN_NAME $GITHUB_RELEASES && chmod +x $BIN_NAME && ./$BIN_NAME"
