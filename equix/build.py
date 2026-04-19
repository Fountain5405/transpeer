#!/usr/bin/env python3
"""Build the EquiX C library from source."""

import subprocess
import sys
from pathlib import Path

EQUIX_REPO = "https://github.com/tevador/equix.git"
EQUIX_DIR = Path(__file__).parent / "equix-src"
BUILD_DIR = EQUIX_DIR / "build"
LIB_OUTPUT = Path(__file__).parent / "libequix.so"


def build():
    if LIB_OUTPUT.exists():
        print(f"libequix.so already exists at {LIB_OUTPUT}")
        return

    # Clone
    if not EQUIX_DIR.exists():
        print("Cloning tevador/equix...")
        subprocess.run(
            ["git", "clone", "--recursive", EQUIX_REPO, str(EQUIX_DIR)],
            check=True,
        )
    else:
        # Ensure submodules are initialized
        subprocess.run(
            ["git", "submodule", "update", "--init", "--recursive"],
            cwd=EQUIX_DIR,
            check=True,
        )

    # Build
    BUILD_DIR.mkdir(exist_ok=True)
    print("Building equix with CMake...")
    subprocess.run(
        ["cmake", "..", "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=ON"],
        cwd=BUILD_DIR,
        check=True,
    )
    subprocess.run(
        ["cmake", "--build", ".", "--config", "Release"],
        cwd=BUILD_DIR,
        check=True,
    )

    # Find and copy the shared library
    for candidate in [
        BUILD_DIR / "libequix.so",
        BUILD_DIR / "src" / "libequix.so",
        BUILD_DIR / "libequix.dylib",
        BUILD_DIR / "src" / "libequix.dylib",
    ]:
        if candidate.exists():
            import shutil
            shutil.copy2(candidate, LIB_OUTPUT)
            print(f"Built successfully: {LIB_OUTPUT}")
            return

    # Search recursively as fallback
    for so in BUILD_DIR.rglob("libequix.*"):
        if so.suffix in (".so", ".dylib"):
            import shutil
            shutil.copy2(so, LIB_OUTPUT)
            print(f"Built successfully: {LIB_OUTPUT}")
            return

    print("ERROR: Could not find built libequix shared library", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    build()
