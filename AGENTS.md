# AGENTS.md

Репозиторий-компаньон mlxini (публичный): собирает образ
`mlxini-ghidra-irisc` (Ghidra 12.1.3 + JDK 21 + процессор iRISC:
slaspec — патч поверх модуля ghidra-processor синдиката, стейджится
slaspec-prep при сборке; java entrypoint-скрипты). Пуш в master на
GitHub — только через PR (master-guard авто-ревертит прямой пуш):
ветка → PR → merge.

## Кодовые правила

- **no-cre-hardcode.** Контейнерный инструмент определяется переменной
  `CRE` (`podman` или `podman-remote`): из toolbx (есть
  `/run/.containerenv`) сборка идёт через хост. Не хардкодить
  `podman`/`podman-remote` в Makefile и скриптах.
- **rm-rf-guard.** `rm -rf` по пути из переменной — только через
  `scripts/safe-rm --under ROOT TARGET...` (копия из llm-rig):
  только абсолютные пути; таргет удаляется, только если равен ROOT или
  лежит под ним; mount point (включая `/`) никогда не удаляется.
- **english-commits.** Сообщения коммитов git — на английском.
