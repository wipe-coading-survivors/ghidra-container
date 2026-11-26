# ghidra-container

Публичный компаньон репозитория
[mlxfwinternals](https://github.com/wipe-coading-survivors/mlxfwinternals):
образ `mlxini-ghidra-irisc` — Ghidra 12.1.3 (SHA-пин) + JDK 21
(SHA-пин) + процессор iRISC + java entrypoint-скрипты Ghidra.

Разработка ведётся из приватного репозитория-источника; имя тега
образа — историческое.

## Канон

- Канон slaspec — патч
  [`scripts/irisc/iRISC.slaspec.patch`](https://github.com/wipe-coading-survivors/mlxfwinternals/blob/bf9d1535ccd69f8f4b2b211dcc58c726d5ed56de/scripts/irisc/iRISC.slaspec.patch)
  в mlxfwinternals@`bf9d1535` — наша дельта поверх upstream-модуля
  `ghidra-processor` синдиката (`4c488a43cdbcef957519e3800c3ba796712d3abb`).
- Здесь — только образ и java-скрипты: `scripts/ghidra/*.java`
  (entrypoint-скрипты Ghidra — `PreFunc`, `Disasm` и др., запекаются
  в образ — часть контракта), `docker/ghidra-irisc.containerfile` +
  `docker/ghidra-decode.sh` + `docker/ghidra-re.sh` — сборка и
  entrypoint образа. Полные slaspec-файлы в этом репозитории не
  живут.

## Сборка

```sh
make image    # docker/ghidra-irisc.containerfile -> тег mlxini-ghidra-irisc
```

`make image` автоматически сначала запускает `slaspec-prep`:
тарболл синдиката@пин + патч@public-SHA, все sha-гейты (integrity
скачанного, upstream-sha slaspec внутри тарболла, result-sha после
патча), стейджинг модуля в `build/processor/` (gitignored). Четыре
переменные prep-источников — `SYNDICATE_TARBALL_URL`,
`SYNDICATE_TARBALL_SHA256`, `SLASPEC_PATCH_URL`,
`SLASPEC_PATCH_SHA256` — переопределяются в `local.mk` или командной
строкой; URL допускает любой scheme, который понимает curl, включая
`file://` — «собирай откуда хочешь» (см. `local.mk.example`).

Голый `podman build .` без prep падает громко: containerfile делает
`COPY build/processor/ …`, а `build/` генерируется только
`slaspec-prep`. Вход задокументирован как `make image`.

Сборка долгая: скачивание JDK 21/Ghidra по SHA-пинам, Sleigh-компиляция
и `.sla`-тест внутри build. Тег образа переопределяется через
`local.mk` (см. `local.mk.example`). Тестов нет (`tests/` отсутствует —
тестировать нечего, образ проверяется in-build гейтами).

## Bump пинов патча

Процедура: патч в mlxfwinternals обновился (новый снапшот@SHA) →
обновить дефолты `SLASPEC_PATCH_URL` и `SLASPEC_PATCH_SHA256` в
Makefile этого репо (URL нового снапшота + sha256 патча из него).
Пины тарболла синдиката меняются только при смене upstream.

## Лицензия

- Лицензия этого репозитория — GPL-3.0 (см. [`LICENSE`](LICENSE)).
- Благодарность [irisc-research-syndicate](https://github.com/irisc-research-syndicate):
  их реверс-инжиниринг iRISC ISA и модуль `ghidra-processor` — основа
  этого пайплайна, без их работы репозитория бы не было. Спасибо.
- Upstream-модуль `ghidra-processor` синдиката не лицензирован: нам
  отказали (issue
  [`irisc-research-syndicate/mlx5cmd#1`](https://github.com/irisc-research-syndicate/mlx5cmd/issues/1),
  закрыт 2026-11-06 «I will not add a license»). Публикуем только свою
  дельту (патч) и собственный код; готовый образ с их модулем внутри
  не редистрибутировать.

## Контракт потребления (mlxfwinternals)

- mlxfwinternals не собирает образ: при отсутствии тега цели-потребители
  (`ghidra-decode`, `ghidra-re`, …) падают с hint на этот репозиторий.
- Чекаут сиблинга: переменная `GHIDRA_CONTAINER_DIR` (дефолт
  `../ghidra-container`, override в `local.mk` mlxfwinternals).
- Dev-цикл java-скриптов: правки `scripts/ghidra/*.java` — здесь;
  `make ghidra-decode-dev` в mlxfwinternals монтирует `scripts/ghidra`
  этого чекаута поверх запечённых скриптов (проверка сиблинга —
  guard-ом, podman не должен молча шадоить запечённые скрипты пустым
  каталогом) — итерации без пересборки образа.

## Crosscheck ISA (mlxfwinternals)

Канон slaspec — патч, канон декодера (`irisc_dis.py`/`enc.py`) —
оба в mlxfwinternals; ISA меняются синхронно:

1. изменить оба канона (патч и декодер — в mlxfwinternals);
2. `make slaspec-gen` (материализует локальные slaspec-копии из
   патча) → `make irisc-crosscheck IMG=<fw-image>`: отчёт штампует
   `ghidra_container_rev` (rev этого чекаута); зафиксировать rev-пару
   (rev mlxfwinternals + rev ghidra-container) в описании изменения —
   дрейф против устаревшего сиблинга виден в каждом отчёте.
