# dep-evidence

Локальный CLI, который собирает **воспроизводимый пакет доказательств** по
open-source-зависимостям из готового CycloneDX SBOM.

Не ещё один vulnerability scanner. Смысл в другом: собрать артефакт, который
можно отдать в enterprise-клиенту или аудитору и который **не меняется** от
запуска к запуску, пока не изменились входные данные.

Три свойства, ради которых это сделано:

1. **Offline по умолчанию.** Сеть нужна ровно один раз — чтобы забрать снапшот
   публичных данных. Дальше `analyze` и `diff` работают только с локальным кэшем.
2. **Детерминизм.** Один и тот же SBOM + один и тот же снапшот дают
   **побайтово одинаковые** файлы. Внутри нет времени запуска, hostname и
   прочих рантайм-меток.
3. **Провенанс.** Каждый снапшот аутентифицирован по SHA-256, и в `sources.json`
   видно, из какого URL и какого дайджеста собраны доказательства.

## Требования

- Python 3.11+
- Никаких зависимостей. Только стандартная библиотека.
- Java, Maven и сеть для `analyze`/`diff` **не нужны**.

## Быстрый старт

```bash
cd /root/dep-evidence
export PYTHONPATH=src
```

### 1. Синхронизация данных (единственная сетевая команда)

```bash
python3 -m dep_evidence sync --cache ./cache \
    --osv-url  https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip \
    --kev-url  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

```text
installed ./cache/snapshots/snapshot-4f1fdf88b24c46cbb41ab1059f845083
```

Скачивание ограничено: есть потолок по размеру скачанного и по размеру
распакованного ZIP (защита от zip-бомб), лимит на ретраи, обработка
`Retry-After`. Установка атомарная — если что-то пошло не так, предыдущий
рабочий снапшот остаётся единственным активным.

### 2. Сбор бандла (offline)

```bash
python3 -m dep_evidence analyze \
    --sbom sbom.json \
    --cache ./cache \
    --exceptions exceptions.json \
    --out ./bundle
```

```text
wrote 6 files to ./bundle
```

SBOM нужен готовый — этот инструмент **не генерирует** SBOM. Подойдёт тот, что
выдал `cyclonedx-maven-plugin`:

```bash
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
```

### 3. Diff между запусками (offline)

```bash
python3 -m dep_evidence diff --before ./bundle-previous --after ./bundle
```

```text
1 added, 1 removed, 2 new, 1 resolved
```

С флагом `--json` выдаётся канонический JSON диффа.

## Что лежит в бандле

| Файл | Содержимое |
|---|---|
| `evidence.json` | Основной документ: компоненты, находки, summary, fingerprint, provenance |
| `report.html` | Самодостаточный отчёт для человека, всё экранировано |
| `components.csv` | **Инвентарь компонентов**, а не отчёт о находках |
| `exceptions.json` | Применённые/известные исключения |
| `sources.json` | Provenance: URL, SHA-256, число записей, версии policy/правил |
| `run_manifest.json` | Метаданные запуска (версия тула, policy, fingerprint) |

### Про `components.csv`

Это именно перечень того, что нашлось в SBOM, — чтобы приложить как
приложение к отчёту. Находки лежат в `evidence.json` и `report.html`.

Если лицензия не декларирована, `license_state` будет `unknown` — это честнее,
чем угадать. Источник известных лицензий при этом сохраняется.

Ячейки, начинающиеся с `=`, `+`, `-`, `@`, нейтрализуются префиксом-апострофом,
чтобы Excel не выполнил содержимое как формулу.

## Исключения

Политика исключений — обычный JSON. Подавляет находку, но **не удаляет её из
provenance**: причина и срок всегда в бандле.

```json
{
  "schema_version": 1,
  "exceptions": [
    {
      "ecosystem": "Maven",
      "package": "com.acme:legacy",
      "advisory_id": "GHSA-bbbb-2222",
      "reason": "end-of-life, tracked in JIRA-1234",
      "expires_on": "2027-01-01"
    }
  ]
}
```

Правило действует, пока `expires_on` не прошёл. Истёкшие правила игнорируются
молча — находка снова всплывает.

## Что означает KEV

Это важно и часто понимают неправильно.

`KEV:known_exploited` означает ровно одно: **этот CVE есть в списке CISA KEV**.
Он не утверждает, что эксплуатировали именно этот Maven-компонент и именно в
вашем приложении.

Сопоставление идёт по точному совпадению CVE-алиаса (`reason: exact_cve_alias`),
без эвристик и догадок. Если совпадения нет — будет
`not_known_exploited`, а не «вроде похоже».

Аналогично: `affected` в OSV означает, что версия попадает в диапазон
уязвимости по данным OSV. Это не утверждение об эксплуатации и не приговор.

## Детерминизм: почему это можно проверять

`evidence.json`, `report.html`, `components.csv`, `sources.json` и
`run_manifest.json` **побайтово совпадают** при повторном запуске на одном
входе. Рантайм-метки живут отдельно и не влияют на эти пять файлов.

`fingerprint` в `evidence.json` — это SHA-256 от нормализованного представления
(SBOM-digest + provenance + версии policy/правил). Одинаковый вход даёт
одинаковый fingerprint, разный — разный. Он годится как ключ для сравнения
в CI:

```bash
python3 -m dep_evidence analyze --sbom sbom.json --cache ./cache --out ./bundle
grep -o '"fingerprint": "[0-9a-f]*"' bundle/evidence.json
```

## Тесты

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B -m unittest discover -s tests
```

```text
Ran 196 tests in 28s
OK
```

Флаги `-B` и `PYTHONDONTWRITEBYTECODE=1` нужны, чтобы в проекте не оставалось
`__pycache__`.

## Структура

```text
src/dep_evidence/
  cli.py          три команды, обработка ошибок без traceback
  sync.py         скачивание, валидация, атомарная установка снапшота
  datasets.py     чтение снапшота по указателю, проверка SHA-256
  sbom.py         парсер CycloneDX JSON
  analysis.py     канонизация компонентов, provenance, fingerprint
  osv.py          сопоставление версий с диапазонами OSV
  kev.py          сопоставление CVE-алиасов с CISA KEV
  versioning.py   сравнение версий
  exceptions.py   политика исключений
  reporting.py    JSON/HTML/CSV-рендереры
  bundle.py       запись бандла
  diffing.py      сравнение двух бандлов
  errors.py       DataError / InputError
```

## Ограничения

Стоит понимать честно, что инструмент **не делает**:

- **Не генерирует SBOM.** Нужен готовый от `cyclonedx-maven-plugin`.
- **Не обновляет зависимости.** Только собирает доказательства.
- **Не даёт compliance и юридических гарантий.** Это не сертификат.
- **Не является непрерывным мониторингом.** Данные не обновляются сами.
- **Не проверяет лицензии на соответствие политике** — только собирает то, что
  декларировано в SBOM.
- **Не призывает CVE-префикс.** Точное совпадение или честный `review`.

Перед любым публичным использованием или redistribut'ом снапшотов отдельно
проверьте условия OSV, CISA KEV и прочих источников.

## Статус

MVP, покрыт тестами и end-to-end прогоном. Git-репозиторий **не инициализирован**.
