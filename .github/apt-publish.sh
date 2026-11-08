#!/usr/bin/env bash

# Adds the .deb files to the APT repository checked out in $1 and rebuilds its signed indexes:
#   .github/apt-publish.sh <repo dir> <file.deb>...
# The pool keeps every version, so the indexes are rebuilt from it alone and the repository needs
# no database. Signs with the only secret key in the keyring, its passphrase in APT_GPG_PASSPHRASE.
# Leaves the rest of the repository (CNAME, README) as it is.
set -euo pipefail

repo="$1"; shift
for deb in "$@"; do
    name=$(dpkg-deb --field "$deb" Package)
    dest="$repo/pool/main/${name:0:1}/$name/$(basename "$deb")"
    # A published version never changes: clients would refuse it, its checksum no longer the one
    # they have. A new build of the same version needs a new version.
    if [ -e "$dest" ] && ! cmp -s "$deb" "$dest"; then
        echo "$(basename "$deb") is already published with other contents: tag a new version" >&2
        exit 1
    fi
    mkdir -p "$(dirname "$dest")"
    cp "$deb" "$dest"
done

cd "$repo"
dist=dists/stable
archs=$(find pool -name '*.deb' | sed -n 's/.*_\([a-z0-9]*\)\.deb$/\1/p' | grep -vx all | sort -u | tr '\n' ' ')
rm -rf "$dist"
for arch in $archs; do
    mkdir -p "$dist/main/binary-$arch"
    apt-ftparchive -a "$arch" packages pool > "$dist/main/binary-$arch/Packages"
    gzip -9 -n -k "$dist/main/binary-$arch/Packages"
done
apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=BeaverMail \
    -o APT::FTPArchive::Release::Label=BeaverMail \
    -o APT::FTPArchive::Release::Suite=stable \
    -o APT::FTPArchive::Release::Codename=stable \
    -o APT::FTPArchive::Release::Architectures="${archs% }" \
    -o APT::FTPArchive::Release::Components=main \
    release "$dist" > "$RUNNER_TEMP/Release"
mv "$RUNNER_TEMP/Release" "$dist/Release"

key=$(gpg --list-secret-keys --with-colons | awk -F: '/^fpr/ { print $10; exit }')
echo "Signing with $key"
sign() { gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 --local-user "$key" "$@" <<< "$APT_GPG_PASSPHRASE"; }
sign --clearsign --output "$dist/InRelease" "$dist/Release"
sign --armor --detach-sign --output "$dist/Release.gpg" "$dist/Release"
# The key users install with signed-by, and no Jekyll pass on Pages.
gpg --export "$key" > beavermail.gpg
touch .nojekyll
