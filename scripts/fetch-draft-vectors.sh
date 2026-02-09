#!/usr/bin/env bash
set -euo pipefail

out_dir="qpgp-pgp/tests/vectors"
draft_url="https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/?format=txt"

mkdir -p "$out_dir"

tmp="$(mktemp)"
curl -sSL "$draft_url" -o "$tmp"

awk -v out="$out_dir" '
  BEGIN {
    n = 0;
    in = 0;
    file = "";
  }
  /^-----BEGIN PGP / {
    in = 1;
    n++;
    kind = "block";
    if ($0 ~ /MESSAGE/) kind = "message";
    else if ($0 ~ /SIGNATURE/) kind = "signature";
    else if ($0 ~ /PUBLIC KEY BLOCK/) kind = "publickey";
    file = sprintf("%s/%s-%02d.asc", out, kind, n);
    print $0 > file;
    next;
  }
  {
    if (in) {
      print $0 >> file;
    }
    if (in && /^-----END PGP /) {
      in = 0;
      file = "";
    }
  }
' "$tmp"

rm -f "$tmp"

count=$(ls -1 "$out_dir"/*.asc 2>/dev/null | wc -l | tr -d ' ')
echo "wrote $count vector files to $out_dir"
