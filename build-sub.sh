#!/usr/bin/env bash
#
# build-sub.sh — сборка endpoint-ов подписки для V2Box из configs.txt
#
#   configs.txt  — источник: по одной ссылке (vless/vmess/ss) на строку.
#                  Пустые строки и строки, начинающиеся с //, игнорируются.
#
#   raw.txt      — тот же список ссылок в plain text (фолбэк: часть сборок
#                  V2Box не умеет base64 и читает подписку как есть).
#
#   sub.txt      — base64 от списка одной строкой без переносов
#                  (на macOS у base64 нет ключа -w, поэтому `base64 | tr -d '\n'`).
#
# Запуск:  ./build-sub.sh
#
set -euo pipefail

# Работаем относительно каталога скрипта — можно запускать из любого места.
cd "$(dirname "$0")"

SRC="configs.txt"
RAW="raw.txt"
SUB="sub.txt"

if [ ! -f "$SRC" ]; then
    echo "error: $SRC не найден" >&2
    exit 1
fi

# Отфильтровать список:
#   - убрать возможный CR (\r) от Windows-переносов;
#   - срезать хвостовые пробелы;
#   - выбросить пустые строки и комментарии (// ...).
filtered="$(sed -e 's/\r$//' -e 's/[[:space:]]*$//' "$SRC" \
    | grep -v -E -e '^[[:space:]]*$' -e '^[[:space:]]*//' || true)"

if [ -z "$filtered" ]; then
    echo "error: в $SRC нет ни одной ссылки" >&2
    exit 1
fi

# raw.txt — plain-list, каждая ссылка на своей строке, перенос LF.
printf '%s\n' "$filtered" > "$RAW"

# sub.txt — base64 от того же списка, одной строкой без переносов.
# Кроссплатформенно: `base64 | tr -d '\n'` работает и на GNU, и на macOS/BSD.
printf '%s\n' "$filtered" | base64 | tr -d '\n' > "$SUB"

count="$(printf '%s\n' "$filtered" | grep -c . || true)"
echo "OK: $count ссылок → $RAW (plain) и $SUB (base64)"
