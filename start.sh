#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

# 1. Если есть скомпилированный бинарник
if [ -f "./dist/psn_scanner" ]; then
    chmod +x ./dist/psn_scanner
    ./dist/psn_scanner "$@"
    exit 0
fi

# 2. Иначе через системный Python
if command -v python3 >/dev/null 2>&1; then
    python3 psn_scanner.py "$@"
    exit 0
fi

echo "Ошибка: Не найден бинарник dist/psn_scanner и не установлен Python!"
exit 1
