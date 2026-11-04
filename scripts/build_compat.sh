#!/bin/bash
set -euo pipefail
project_dir="$(cd "$(dirname "$0")/.." && pwd)"
sdk_path="$(xcrun --sdk macosx --show-sdk-path)"
mkdir -p "$project_dir/build"
xcrun clang -target arm64-apple-ios15.0-macabi \
  -isysroot "$sdk_path" -iframework "$sdk_path/System/iOSSupport/System/Library/Frameworks" \
  -fobjc-arc -dynamiclib \
  -framework Foundation -framework Security -framework GameController -framework UIKit -framework QuartzCore \
  -framework CoreGraphics \
  -install_name @executable_path/Frameworks/libmcmac.dylib \
  -Wall -Wextra \
  "$project_dir/compat/mcmac.m" "$project_dir/compat/legacy_keychain.m" \
  "$project_dir/compat/key_items.m" "$project_dir/compat/key_generation.m" \
  "$project_dir/compat/input.m" \
  "$project_dir/compat/termination.m" "$project_dir/compat/synthetic_mouse.m" \
  "$project_dir/compat/runloop.m" "$project_dir/compat/synthetic_keyboard.m" \
  "$project_dir/compat/keyboard_routing.m" \
  "$project_dir/compat/button_state.m" \
  "$project_dir/compat/display_metrics.m" \
  "$project_dir/compat/geometry.m" \
  -o "$project_dir/build/libmcmac.dylib"
codesign --force --sign - --timestamp=none "$project_dir/build/libmcmac.dylib"
