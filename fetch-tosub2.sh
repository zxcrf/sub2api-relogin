#!/bin/sh
# 在服务器上重建 vendor/tosub2：按固定提交下载，校验压缩包哈希，打补丁，再按清单逐文件校验。
set -eu
COMMIT=8548397e89bf80e508eda64a87e0d556d43abc84
TARBALL_SHA256=ddb061cff7c87b5c931615ef10e904795852a6bfef8f23d9998634ca77ade9a0
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "https://codeload.github.com/poxiao33/toSub2/tar.gz/$COMMIT" -o "$tmp/tosub2.tgz"
echo "$TARBALL_SHA256  $tmp/tosub2.tgz" | sha256sum -c -
mkdir "$tmp/src"
tar -xzf "$tmp/tosub2.tgz" --strip-components=1 -C "$tmp/src"
rm -rf vendor/tosub2
mkdir -p vendor/tosub2
cp -R "$tmp/src/src" "$tmp/src/LICENSE" "$tmp/src/package.json" "$tmp/src/requirements.txt" vendor/tosub2/
echo "$COMMIT" > vendor/tosub2/UPSTREAM_COMMIT
for p in patches/*.patch; do patch -s -p1 -d vendor/tosub2 < "$p"; done
(cd vendor/tosub2 && sha256sum -c --quiet ../tosub2.sha256)
echo "vendor/tosub2 已重建并校验通过"
