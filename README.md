# PSN Trophy Scanner

Сбор игроков PSN по выбитому трофею в игре с фильтрацией по дате и сохранением в TXT.

## Запуск (Python не требуется)

- **Windows:** запустите `start.bat` (двойным кликом).
- **Linux:** запустите `./start.sh` (или `./dist/psn_scanner --config config.json`).

## Быстрая настройка

1. **NPSSO токен:**
   Войдите в аккаунт на [store.playstation.com](https://store.playstation.com/), затем откройте [ca.account.sony.com/api/v1/ssocookie](https://ca.account.sony.com/api/v1/ssocookie) и скопируйте значение `npsso`.

2. **Конфигурация (`config.json`):**
```json
{
  "npsso": "ВАШ_NPSSO_ТОКЕН",
  "game": "NPWR20188_00",
  "trophy_id": 0,
  "date_from": "2024-01-01",
  "date_to": "2024-12-31",
  "accounts_file": "accounts.txt",
  "output_file": "results.txt",
  "concurrency": 3,
  "delay": 0.3
}
```
*Параметр `trophy_id`: `0` — Платина (по умолчанию), число — конкретный ID, `"all"` — любой выбитый трофей.*

3. **Список игроков (`accounts.txt`):**
   Внесите никнеймы (или ID аккаунтов) по одному на строку:
```text
Hakoom
RoughDawg4
```

## Результаты

Найденные игроки записываются в `results.txt` в реальном времени:
```text
Hakoom | 1111222233334444555 | Трофей #0 [PLATINUM] 'Master Trophy' | Выбит: 2024-05-10T14:20:00Z
```
