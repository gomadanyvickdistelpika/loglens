#!/usr/bin/env sh
# Linux launcher: no dependencies besides Python 3.9+ (poppler-utils optional, for TDLog PDFs).
cd "$(dirname "$0")" || exit 1
exec python3 -m lvx serve --open "$@"
