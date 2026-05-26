# HookModBase — Modular C++ DLL Modding SDK Template

[English](#english) | [Русский](#русский)

---

## English

**HookModBase** is a lightweight, structured C++ DLL template designed for reverse engineering, debugging, and game modding. 

Unlike raw hooking libraries, this project focuses on **software architecture**—providing a clean, object-oriented framework to organize multiple hook subsystems into modular classes rather than a cluttered single file.

---

### Key Features

*   **Modular Architecture (`IHookModule` & `HookManager`):** Encourages clean code by separating mod features (e.g., `InputHook`, `GraphicsHook`) into isolated classes with standardized lifecycles.
*   **Safe Memory Rollback (`HookTracker`):** Automatically tracks overwritten bytes and restores original code in strict Last-In-First-Out (LIFO) order during DLL unloading, minimizing process crashes.
*   **IDA Pro Symbol Resolver (`SymbolResolver`):** Imports standard TAB-separated export lists from IDA Pro to automatically resolve raw virtual addresses to named functions in debug logs.
*   **Visual Tree Diagnostics:** Logs detailed hooking structure (with NOP-regions and parent call-sites) to `OutputDebugString` using tree-like graphics (`|-`, `\_`).
*   **Clean Memory Wrapper (`MemoryEx`):** Implements type-safe memory operations using `uintptr_t` to ensure compatibility across x86 and x64 platforms.

---

### Technical Limits & Caveats

To keep the codebase lightweight and highly readable, the following design trade-offs were made:
1.  **No Length Disassembler Engine (LDE):** The SDK does not automatically calculate instruction lengths for inline hooks on the fly. The developer is responsible for specifying correct instruction bounds or filling remaining space with NOPs.
2.  **No Runtime Trampoline Generator:** The project is designed for complete function hijacking (replacement) or direct call-site patching. To call original functions inline, you must handle the assembly stub manually or integrate a low-level engine like *MinHook* or *Microsoft Detours* inside the `MemoryEx` implementation.

---

### Repository Structure

```text
├── HookModBase.sln                 # MSBuild Solution
├── HookModBase/                    # DLL Project (Dynamic Library)
│   ├── include/                    # SDK Header files
│   ├── src/                        # Core SDK Implementation
│   ├── example/                    # TestAppHook module implementation
│   └── dllmain.cpp                 # DLL entry point and thread setup
└── TargetApp/                      # Test EXE Project (Console Mock Engine)
    └── main.cpp                    # Hook target loop
```

---

### Quick Start

1.  Open `HookModBase.sln` in Visual Studio (configured for **Release | x86**).
2.  Build the solution.
3.  Navigate to the generated output directory (e.g., `examples/`) containing `TargetApp.exe`, `HookModBase.dll`, and `ida_exports.txt`.
4.  Run `TargetApp.exe`. You will see the original output for 2 frames, after which the background thread in the DLL successfully hooks the execution flow.

#### Creating a custom module:

```cpp
#include "IHookModule.h"
#include "MemoryEx.h"
#include "Utils.h"

class MyModModule : public IHookModule
{
public:
    const char* GetName() const override { return "MyModModule"; }

    bool Init() override {
        uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
        
        // Setup an inline Jmp hook
        m_tracker.InstallHook(
            base + 0x1140, 
            HookType::Jmp, 
            reinterpret_cast<uintptr_t>(MyDetour), 
            "TargetClass::TargetMethod"
        );
        return true;
    }

    void Shutdown() override {
        m_tracker.RestoreAll(); // Safely rolls back changes
    }
};
```

---

## Русский

**HookModBase** — это легковесный, структурированный шаблон C++ DLL, разработанный для задач реверс-инжиниринга, отладки и создания игровых модификаций.

В отличие от низкоуровневых библиотек перехвата, этот проект сфокусирован на **архитектуре программного кода**. Он предоставляет объектно-ориентированную структуру для разделения различных подсистем хуков на изолированные модули, предотвращая накопление хаотичного кода в одной точке входа.

---

### Ключевые возможности

*   **Модульная архитектура (`IHookModule` и `HookManager`):** Позволяет разносить функционал мода (например, работу с вводом `InputHook`, графикой `GraphicsHook`) по независимым классам со стандартизированным жизненным циклом.
*   **Безопасный откат памяти (`HookTracker`):** Автоматически отслеживает измененные байты и восстанавливает оригинальный код в строгом порядке LIFO (Last-In-First-Out) при выгрузке DLL, предотвращая падение целевого процесса.
*   **Разрешение символов IDA Pro (`SymbolResolver`):** Импортирует текстовые файлы экспорта функций из IDA Pro (разделенные табуляцией) для автоматического преобразования адресов памяти в осмысленные имена функций в логах отладки.
*   **Наглядная древовидная диагностика:** Выводит подробную структуру установленных хуков и затертых NOP-регионов в `OutputDebugString` в виде наглядного дерева с использованием символов псевдографики (`|-`, `\_`).
*   **Безопасная работа с памятью (`MemoryEx`):** Использует строго типизированные указатели `uintptr_t`, исключая срез адресов и обеспечивая переносимость кода.

---

### Технические ограничения

Для сохранения простоты чтения и легковесности кода были приняты следующие архитектурные компромиссы:
1.  **Отсутствие дизассемблера длин (LDE):** Шаблон не вычисляет размер инструкций на лету. Разработчик должен самостоятельно контролировать границы изменяемых инструкций или забивать оставшееся место NOP-командами.
2.  **Отсутствие генератора трамплинов во время выполнения:** Проект ориентирован на полное замещение логики (hijacking) или патчинг адресов вызова (call-site). Для вызова оригинальной функции изнутри хука разработчику потребуется реализовать ассемблерный мост вручную или интегрировать решение класса *MinHook* / *Microsoft Detours* на уровне `MemoryEx`.

---

### Структура репозитория

```text
├── HookModBase.sln                 # Файл решения MSBuild (Visual Studio)
├── HookModBase/                    # Проект DLL (Динамическая библиотека)
│   ├── include/                    # Заголовочные файлы SDK
│   ├── src/                        # Исходный код ядра SDK
│   ├── example/                    # Реализация тестового модуля TestAppHook
│   └── dllmain.cpp                 # Точка входа DLL и запуск рабочего потока
└── TargetApp/                      # Тестовый проект EXE (Консольное приложение)
    └── main.cpp                    # Имитация игрового цикла
```

---

### Быстрый старт

1.  Откройте файл `HookModBase.sln` в Visual Studio (рекомендуется конфигурация **Release | x86**).
2.  Соберите решение (Build Solution).
3.  Перейдите в созданный каталог (например, `examples/`), содержащий собранные `TargetApp.exe`, `HookModBase.dll` и файл `ida_exports.txt`.
4.  Запустите `TargetApp.exe`. Первые два кадра выполнится оригинальный код, после чего фоновый поток DLL применит хуки и перехватит выполнение.

#### Пример создания собственного модуля:

```cpp
#include "IHookModule.h"
#include "MemoryEx.h"
#include "Utils.h"

class MyModModule : public IHookModule
{
public:
    const char* GetName() const override { return "MyModModule"; }

    bool Init() override {
        uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
        
        // Установка стандартного inline-перехода (Jmp Hook)
        m_tracker.InstallHook(
            base + 0x1140, 
            HookType::Jmp, 
            reinterpret_cast<uintptr_t>(MyDetour), 
            "TargetClass::TargetMethod"
        );
        return true;
    }

    void Shutdown() override {
        m_tracker.RestoreAll(); // Безопасно восстанавливает оригинальные байты
    }
};
```