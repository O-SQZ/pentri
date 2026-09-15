#!/bin/sh
cd "$(dirname "$0")" || exit 1
if [ -x ./runtime/node ]; then
  exec ./runtime/node scripts/desktop.mjs
fi
if ! command -v node >/dev/null 2>&1; then
  echo 'Node.js 24.14 이상 24.x를 설치하거나 런타임 포함 배포본을 사용하세요.'
  exit 1
fi
exec node scripts/desktop.mjs
