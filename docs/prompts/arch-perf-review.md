# Architecture & performance review — reusable prompts

Two prompts, each run in a fresh session (after `/clear`): prompt 1 once (read-only audit that
produces a batch in `docs/TASKS.md`), prompt 2 once per sub-batch after the owner approves the
batch plan.

## Prompt 1 — audit (read-only)

```
Роль: ти одночасно senior-архітектор і performance-інженер. Проведи глибокий аудит
коду cipher_ua, лише читання: жодних змін у коді, тільки документ із
знахідками. Результат — новий батч задач у docs/TASKS.md.

## 0. Перед аналізом прочитай (обов'язково, повністю)
- CLAUDE.md (проєктний) і ~/.claude/CLAUDE.md, ~/.claude/dev-practices.md
- docs/dstu-crypto-project.md, docs/DECISIONS.md, docs/SECURITY.md,
  docs/PERFORMANCE.md, docs/resource-profiles.md, docs/rust_ai_ruleset.md,
  docs/cross-language-style-guide.md, docs/bindings-strategy.md
- docs/TASKS.md: розділ "Security audit remediation (2026-09-22)", його список
  "Clean areas" (їх НЕ перевіряти повторно) і всі відкриті задачі, щоб не
  дублювати вже відоме.
Зафіксуй на початку звіту commit hash і версії крейтів — це стан, який аудитується.

## 1. Зона аудиту
crates/dstu-core (hazmat + crypto_* + selftest), crates/uacrypt,
crates/dstu-core-capi, xtask, fuzz/, firmware/, .github/workflows,
bindings/* (усі 8, кожен — окремий workspace, D-119).

## 2. Архітектурна лінза
- Розшарування hazmat → crypto_* (D-09): чи не протікають hazmat-типи/кноби в
  crypto_*; чи дотримано D-47 "delete the knob"; misuse resistance API.
- Межі крейтів і feature flags: чистота no_std/alloc/std, адитивна уніфікація
  фіч (D-50, D-74, D-164), cfg-гейтовані варіанти публічних enum.
- C ABI: стабільність, власність пам'яті, узгодженість DstuStatus, catch_unwind.
- Байндинги: дубльована логіка, яка має жити в ядрі (D-118), розбіжність форми
  API між мовами, обидві пастки D-118 у кожному з 8 (T-249 лишив 6 перевіреними
  тільки grep'ом).
- Wire-формати: версіонування, покриття nonce і довжини тегом (D-63/D-200).
- Конвенції з ~/.claude/CLAUDE.md: bounds-перевірка, доказова з самого рядка
  (>= замість ==), const/readonly, відсутність рекурсії, RAII/Drop, мінімальні
  абстракції, дублювання.
- Тести: чотири категорії (+ active-attack для асиметричних примітивів), яких
  тестів БРАКУЄ (так знайшли D-63), формульні передумови без явного
  граничного тесту (D-109–D-111).
- QA-інфраструктура: xtask ci проти CI-воркфлоу — розсинхрон (FUZZ_TARGETS
  тощо), шари, які тихо пропускаються.

## 3. Performance-лінза
- Гарячі шляхи Kalyna/Kupyna/Strumok/GCM/CMAC/DSTU 4145/9041: зайві копії,
  алокації в циклах, bounds checks у внутрішніх циклах, незмерджені проходи,
  Zeroize-оверхед, розмір таблиць (fused vs small-tables).
- Потокові шляхи: uacrypt і секретстрім — чи пам'ять справді обмежена (D-42),
  розмір чанків, подвійна буферизація, syscalls.
- FFI: копіювання через межу, зайві алокації на виклик, у кожному з 8 байндингів.
- Асиметрія: кількість інверсій/множень, повторні обчислення, які можна
  прекомп'ютити без втрати constant-time.
- Жорсткі правила: жодна оптимізація, що вводить secret-dependent branching або
  нове secret-dependent індексування поза D-19. Кожну гіпотезу щодо
  kalyna/kupyna/strumok перевір через --emit=asm, а не з вихідного коду
  (T-139/T-129). Порівняння між реалізаціями — тільки зібраний бінарник, MB/s
  (D-34/D-170). Пастка stale-бінарника після git stash (D-161).
- Performance-знахідка без виміру — це максимум "Plausible", не "Confirmed".

## 4. Стандарт доказовості
Кожна знахідка: file:line; яке правило/D-запис/конвенцію порушено (з
цитатою); статус Confirmed (відтворено тестом, PoC або виміром) / Plausible /
Note; для Confirmed — рецепт відтворення, який переживе сесію (PoC-крейти поза
репо зникнуть, тож команди й вектори пиши прямо в задачу). Без спекулятивних
знахідок і без "можна було б гарніше" без конкретного ризику чи
виміряної вартості. PQ-треки (D-08) не пропонувати.

Якщо знахідка — живий security-баг: НЕ пушити (див. memory про embargo
2026-09), позначити окремо і зупинитися на цьому пункті з питанням до мене.

## 5. Результат
Новий розділ у docs/TASKS.md:
"## Architecture & performance review (<дата>, read-only audit at <commit>)".
- Вступ: зона аудиту, метод, стан, список Clean areas (перевірено, нічого не
  знайдено — щоб повторний аудит не дублював).
- Задачі з новими T-ID (продовж нумерацію; перевір grep'ом максимальний
  наявний). Для кожної: severity (Critical/High/Medium/Low), категорія
  (arch/perf/test-gap/qa/docs), доказ, рецепт відтворення, напрям виправлення
  (не реалізація), які категорії тестів потрібні, ризик регресії, зусилля (S/M/L),
  залежності від інших T-ID.
- "Owner decisions needed" — розвилки, які не можна вирішити за правилами
  проєкту. Для кожної: прості наслідки кожного варіанта. Не обирай сам.
- "Batch plan": розбий знахідки на підбатчі (3a/3b/... як у розділі FFI roadmap)
  за залежностями, модулем і ризиком: спершу безпека/коректність, потім
  test-gap, потім arch, потім perf (perf — лише після того, як тести
  зафіксували поведінку). Для кожного підбатча: склад, чому саме такий
  порядок, критерій готовності, чи потрібні plan mode + advisor.
- "RESUME HERE" для передачі в нову сесію.

## 6. Процес
- Не спавнити субагентів (або: дозволяю Explore-агентів для fan-out по
  bindings/ — лишити одне з двох).
- Перед написанням розділу — advisor щодо повноти й пріоритизації; після
  коміту документа — закривний advisor.
- Коміт: тільки docs/TASKS.md (+ DECISIONS.md, якщо з'явились finding-записи),
  без пушу. Наприкінці — короткий підсумок українською: скільки знахідок за
  severity, які розвилки чекають на мене, запропонований порядок підбатчів.
  Далі чекай мого затвердження batch plan.
```

## Prompt 2 — execute one sub-batch (run once per sub-batch)

```
Виконай підбатч <3a> з розділу "Architecture & performance review" у
docs/TASKS.md. Спершу прочитай розділ повністю, включно з "RESUME HERE" і
вирішеними owner decisions.

Правила:
- Plan mode → план → advisor ДО реалізації (якщо підбатч позначений як такий).
- Test-first: спершу тест, що падає, або вимір-бейзлайн; чотири категорії
  (+ active-attack для асиметричних примітивів).
- Perf-зміни: бейзлайн до/після на зібраному бінарнику (MB/s) плюс criterion;
  для kalyna/kupyna/strumok — перевірка asm; жодної нової secret-dependent
  гілки. Результати — у docs/PERFORMANCE.md.
- Мінімальні диффи, тільки скоуп підбатча. Нова розвилка → зупинись і спитай,
  або збери всі розвилки в одне повідомлення наприкінці.
- Після кожної задачі: cargo xtask ci (обов'язкові шари зелені) плюс збірка й
  тести зачеплених байндингів; окремий коміт на задачу з T-ID.
- Doc-map sweep: grep T-ID по файлах з колонки "Update when"; окремо
  перечитати "Project status" у CLAUDE.md і [Unreleased] у CHANGELOG.
- Durable-результат (коміти) → закривний advisor → оновити "RESUME HERE".
- Пуш тільки з мого дозволу; після пушу — gh run list/view.
```
