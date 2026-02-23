#!/bin/bash

# Exit the script on any error
set -e

# Define installation directories
INSTALL_DIR="$(pwd)"  # Current working directory (absolute path)
REPO_DIR="${INSTALL_DIR}/liboqs"
BUILD_DIR="${REPO_DIR}/build"

# Install required dependencies
echo "Installing required dependencies..."
sudo apt update
sudo apt install -y astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind git

# Clone the liboqs repository if it doesn't exist
if [ ! -d "$REPO_DIR" ]; then
    echo "Cloning liboqs repository into $REPO_DIR..."
    git clone -b main https://github.com/open-quantum-safe/liboqs.git "$REPO_DIR"
else
    echo "liboqs repository already exists at $REPO_DIR."
fi

# Build liboqs
echo "Configuring the build..."
mkdir -p "$BUILD_DIR"  # Create build directory if it doesn't exist
cd "$BUILD_DIR"

echo "Running cmake to configure the build..."
cmake -GNinja "$REPO_DIR"

echo "Building liboqs using Ninja..."
sudo ninja install

# Return to the installation directory and run make all
cd "$INSTALL_DIR"
echo "Running make all in the root directory..."
make all

echo "Installation complete."

