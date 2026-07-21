# Rust Best Practices & Architecture Ruleset
Comprehensive System Prompt / Ruleset for AI Assistants (Claude Code, Cursor)

## 1. Fundamental Memory & Ownership Patterns
* **RAII (Resource Acquisition Is Initialization)**:
  * Інкапсулюй ресурси (файли, сокети, локи) у структури. Завжди покладайся на автоматичний виклик `Drop` замість ручного закриття/звільнення.
* **Borrow Checker-Friendly Design**:
  * Дотримуйся принципу **Single Ownership**. Уникайте циклічних посилань.
  * Якщо можливий розрив володіння, віддавай перевагу **Arena Allocation** (наприклад, через crate `typed-arena` або index-based arrays) замість каскаду `Arc<Mutex<T>>`.
* **Zero-Cost Abstractions & Zero-Copy**:
  * Використовуй **`Cow<'a, T>`** (Clone-On-Write) для випадків, коли дані частіше читаються, ніж модифікуються.
  * Приймай у функціях запозичені типи за їхніми **Deref Target** (`&str` замість `&String`, `&[T]` замість `&Vec<T>`).

## 2. Type System & Compile-Time Guarantees
* **Type-State Pattern (Compile-Time State Machine)**:
  * Кодуй стан системи через Generics та Zero-Sized Types (`PhantomData<T>`). Переходи між станами повинні споживати об'єкт через `self` (Move semantics).
* **Newtype Pattern**:
  * Огортай примітивні типи у кортежні структури (`struct UserId(u64);`), щоб виключити класичну помилку `Primitive Obsession` та переплутування аргументів.
* **Exhaustive Pattern Matching & Algebraic Data Types (ADT)**:
  * Моделюй взаємовиключні дані через `enum`.
  * Не використовуй wildcard `_` у `match` без критичної потреби, щоб розширення `enum` автоматично викликало помилки компіляції в місцях обробки.
* **Make Illegal States Unrepresentable**:
  * Конструюй структури так, щоб невалідний стан об'єкта був неможливий на рівні типів (відсутність "прапорців" `is_valid`, `is_connected` всередині структур).

## 3. API Conventions & Standard Traits
* **C-CONVENTION (Rust API Guidelines)**:
  * `to_` — дороговартісна конвертація (`to_string()`).
  * `as_` — безкоштовне запозичення (`as_bytes()`).
  * `into_` — конвертація із поглинанням володіння (`into_vec()`).
* **Canonical Trait Implementations**:
  * Для всіх публічних типів обов'язково реалізовувати або деDerived: `Debug`, `Send`, `Sync` (якщо безпечно), `Default`.
  * Замість методів `parse()` чи `from_...()` реалізовуй канонічні трейти `From<T>`, `TryFrom<T>`, `FromStr`.

## 4. Error Handling Architecture
* **Panic-Free Production Code**:
  * Повна заборона `.unwrap()`, `.expect()`, `panic!()` та `unreachable!()` у продакшн-коді.
* **Error Separation (Libraries vs Applications)**:
  * **Library Errors (Domain Errors)**: Використовуй `thiserror` для створення строго типізованих `enum Error`.
  * **Application Errors (Contextual Errors)**: Використовуй `anyhow::Result` або `eyre::Result` із додаванням контексту через `.context("...")`.

## 5. Idiomatic Performance & Functional Pipeline
* **Internal Iteration & Bound-Check Elimination**:
  * Надавай перевагу ітераторним ланцюжкам (`map`, `filter`, `fold`, `collect`) замість явних циклів `for i in 0..len` — це дозволяє компілятору прибирати перевірки меж масиву (Bound Checks).
* **Small-Buffer Optimization (SBO)**:
  * Використовуй `SmallVec` або `ArrayVec` для колекцій, де середня кількість елементів мала і відома на етапі компіляції.

## 6. Safety & Unsafe Code Boundaries
* **Encapsulated Unsafe & Soundness**:
  * Весь `unsafe` код повинен бути ізольований у найменшому можливому модулі із safe-обгорткою.
* **Safety Invariant Documentation**:
  * Кожна `unsafe fn` або блок `unsafe` зобов'язані мати коментар у форматі:
    `// SAFETY: <обґрунтування, чому інваріанти пам'яті дотримані>`.

## 7. Concurrency & Async
* **Send & Sync Boundaries**:
  * Перевіряй потокобезпеку на рівні типів: `Send` (передача між потоками), `Sync` (доступ з кількох потоків через посилання).
* **Non-Blocking Async Execution**:
  * Уникнення будь-яких синхронних / blocking I/O чи довготривалих CPU-bound обчислень всередині async-тасок. Для обчислень використовувати `tokio::task::spawn_blocking`.

## 8. Visibility & Modularity (Інкапсуляція)
* **Principle of Least Privilege (Мінімальна видимість)**:
  * Заборонено використовувати `pub` за замовчуванням. Всі внутрішні структури та функції мають бути `pub(crate)`, `pub(super)` або приватними.
  * Експортуй назовні (через `pub`) виключно фінальний публічний API крейту.
* **Workspace Pattern**:
  * Для середніх і великих проєктів розбивай моноліт на незалежні крейти через `[workspace]`. Кожен крейт має відповідати за один домен.

## 9. Lints & Static Analysis (Контроль якості)
* **Clippy as a Compiler**:
  * AI має генерувати код, який проходить перевірку з увімкненими педантичними лінтерами.
  * Вимагається додавати на рівні `lib.rs` / `main.rs` директиви:
    ```rust
    #![warn(clippy::pedantic)]
    #![deny(clippy::unwrap_used, clippy::expect_used)]
    ```

## 10. Documentation & Doc-tests
* **Executable Documentation**:
  * Усі публічні структури, трейти та функції (з модифікатором `pub`) зобов'язані мати `///` Rustdoc-коментар.
  * Документація для ключових функцій **повинна містити приклади коду** в блоках ` ```rust `, які автоматично стають інтеграційними тестами (Doc-tests).
* **Enforce Documentation**:
  * Для бібліотечних крейтів використовувати директиву `#![warn(missing_docs)]`.

## 11. Testing Conventions (Тестування)
* **Inline Unit Tests**:
  * Модульні тести для перевірки приватної логіки повинні знаходитись у тому ж файлі, що й тестований код, у модулі `#[cfg(test)] mod tests { ... }`.
* **Black-Box Integration Tests**:
  * Тестування публічного API має виноситися в окрему директорію `tests/` у корені проєкту.
* **Trait-based Dependency Injection**:
  * Для можливості мокування (mocking) залежностей у тестах (наприклад, доступу до БД або мережі), абстрагуй їх через трейти, приймаючи як `&dyn Trait` або `impl Trait`.

## 12. Macros Boundaries (Межі макросів)
* **Compile-Time Awareness**:
  * Заборонено створювати нові кастомні **Procedural Macros** без критичної на те потреби, оскільки вони драматично збільшують час компіляції.
  * Для кодогенерації чи уникнення дублювання (Boilerplate) надавай перевагу декларативним макросам (`macro_rules!`) або системі Generics/Traits.
