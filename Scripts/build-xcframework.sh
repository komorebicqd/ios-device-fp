#!/usr/bin/env bash
#
# 构建可分发的 DeviceFingerprintSDK.xcframework（iOS Device + iOS Simulator）。
#
# 仅在 macOS + Xcode 环境执行：
#   bash Scripts/build-xcframework.sh
#
# 产物：
#   .build/distribution/DeviceFingerprintSDK.xcframework
#   .build/distribution/DeviceFingerprintSDK.xcframework.zip
# 末尾会输出 SHA256，供 binaryTarget 的 checksum 使用。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="${ROOT}/Distribution/DeviceFingerprintSDK.xcodeproj"
SCHEME="DeviceFingerprintSDK"
NAME="DeviceFingerprintSDK"
BUILD_DIR="${ROOT}/.build/distribution"

rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

archive_slice() {
  local destination="$1"
  local archive_path="$2"

  xcodebuild archive \
    -project "${PROJECT}" \
    -scheme "${SCHEME}" \
    -configuration Release \
    -destination "${destination}" \
    -archivePath "${archive_path}" \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
    CODE_SIGNING_ALLOWED=NO \
    -quiet
}

echo "==> 归档 iOS Device"
archive_slice "generic/platform=iOS" "${BUILD_DIR}/ios.xcarchive"

echo "==> 归档 iOS Simulator"
archive_slice "generic/platform=iOS Simulator" "${BUILD_DIR}/simulator.xcarchive"

find_framework() {
  local archive_path="$1"
  local framework_path
  framework_path="$(find "${archive_path}" -type d -name "${NAME}.framework" | head -n 1)"
  if [ -z "${framework_path}" ]; then
    echo "error: 在 ${archive_path} 中找不到 ${NAME}.framework" >&2
    exit 1
  fi
  echo "${framework_path}"
}

DEVICE_FRAMEWORK="$(find_framework "${BUILD_DIR}/ios.xcarchive")"
SIMULATOR_FRAMEWORK="$(find_framework "${BUILD_DIR}/simulator.xcarchive")"

echo "==> 合并 XCFramework"
rm -rf "${BUILD_DIR}/${NAME}.xcframework"
xcodebuild -create-xcframework \
  -framework "${DEVICE_FRAMEWORK}" \
  -framework "${SIMULATOR_FRAMEWORK}" \
  -output "${BUILD_DIR}/${NAME}.xcframework"

echo "==> 打包 zip"
ditto -c -k --sequesterRsrc --keepParent \
  "${BUILD_DIR}/${NAME}.xcframework" \
  "${BUILD_DIR}/${NAME}.xcframework.zip"

SUM="$(shasum -a 256 "${BUILD_DIR}/${NAME}.xcframework.zip" | awk '{print $1}')"
SIZE="$(du -h "${BUILD_DIR}/${NAME}.xcframework.zip" | awk '{print $1}')"

echo "==> 完成"
echo "XCFRAMEWORK=${BUILD_DIR}/${NAME}.xcframework.zip (${SIZE})"
echo "SHA256=${SUM}"
