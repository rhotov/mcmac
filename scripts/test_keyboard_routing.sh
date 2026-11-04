#!/bin/bash
set -euo pipefail
project_dir="$(cd "$(dirname "$0")/.." && pwd)"
sdk_path="$(xcrun --sdk macosx --show-sdk-path)"
mkdir -p "$project_dir/build"
xcrun clang -target arm64-apple-ios15.0-macabi \
  -isysroot "$sdk_path" -iframework "$sdk_path/System/iOSSupport/System/Library/Frameworks" \
  -fobjc-arc -Wall -Wextra -Werror -framework Foundation -framework UIKit -framework GameController \
  "$project_dir/tests/keyboard_routing_smoke.m" -o "$project_dir/build/keyboard_routing_smoke"
"$project_dir/build/keyboard_routing_smoke"
