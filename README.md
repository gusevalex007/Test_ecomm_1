# V2Box subscription endpoint

Статическая подписка для [V2Box], раздаётся через GitHub Pages.

Корень сайта: **https://gusevalex007.github.io/Test_ecomm_1/**

## Файлы

| Файл | Назначение |
|------|-----------|
| `configs.txt` | Источник. По одной ссылке (`vless://` / `vmess://` / `ss://`) на строку. Правится вручную. |
| `build-sub.sh` | Сборка `raw.txt` и `sub.txt` из `configs.txt`. |
| `raw.txt` | Список ссылок в plain text. Фолбэк-подписка для сборок V2Box, которые не парсят base64. |
| `sub.txt` | Тот же список в base64 одной строкой. Основная подписка. |
| `vpn.html` | Памятка с адресами подписки и кнопками «копировать». |
| `.nojekyll` | Отключает Jekyll, чтобы Pages отдавал файлы как есть. |

## Адреса подписки (вставлять в V2Box → Add Subscription)

- Основная (base64): `https://gusevalex007.github.io/Test_ecomm_1/sub.txt`
- Фолбэк (plain):    `https://gusevalex007.github.io/Test_ecomm_1/raw.txt`

## Как добавить или изменить конфиг

1. Отредактируйте `configs.txt` — добавьте ссылку новой строкой.
   - Пустые строки игнорируются.
   - Строки, начинающиеся с `//`, считаются комментариями и в подписку не попадают.
2. Пересоберите подписку:
   ```sh
   ./build-sub.sh
   ```
   Скрипт перезапишет `raw.txt` и `sub.txt`.
3. Закоммитьте и запушьте изменения:
   ```sh
   git add configs.txt raw.txt sub.txt
   git commit -m "Update subscription"
   git push
   ```
4. GitHub Pages задеплоит новые файлы автоматически. V2Box подтянет их при следующем обновлении подписки.

## Формат

`sub.txt` — это `base64( список_ссылок )`, где список — строки, разделённые `\n`.
V2Box декодирует base64 и разбивает результат по переводам строк.

Скрипт кроссплатформенный: на macOS у `base64` нет ключа `-w`, поэтому переносы
убираются через `base64 | tr -d '\n'`.

[V2Box]: https://apps.apple.com/app/v2box-v2ray-client/id6446814690
