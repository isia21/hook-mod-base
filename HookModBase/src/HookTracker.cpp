#include "stdafx.h"
#include "../include/MemoryEx.h"
#include "../include/Utils.h"
#include "../include/SymbolResolver.h"

/// <summary>
/// Вспомогательная локальная функция для простого объединения вектора строк через разделитель.
/// </summary>
static std::string join_strings(const std::vector<std::string>& vec, const std::string& separator)
{
    if (vec.empty()) return "";

    return std::accumulate(std::next(vec.begin()), vec.end(), vec[0],
        [&separator](const std::string& a, const std::string& b) {
            return a + separator + b;
        });
}

/// <summary>
/// Вспомогательная локальная функция форматирования списка адресов (callers) в структурированный 
/// многострочный древовидный вид с автоматическим разрешением символов через SymbolResolver.
/// </summary>
static std::string join_resolved_multiline(const std::vector<uintptr_t>& vec, const std::string& linePrefix, size_t perLine = 3)
{
    if (vec.empty()) return "";

    std::string result;
    // Сдвиг вправо, чтобы выровнять адреса под заголовок "(Called from: "
    std::string indent = "\n       " + linePrefix + "               ";

    for (size_t i = 0; i < vec.size(); ++i) {
        std::string name = SymbolResolver::Instance().Resolve(vec[i]);

        // Используем выравнивание по левому краю шириной в 64 символа для поддержки длинных имен из IDA
        char buf[64];
        snprintf(buf, sizeof(buf), "%-64s", name.c_str());
        result += buf;

        if (i < vec.size() - 1) {
            result += ", ";

            // Перенос строки при достижении лимита колонок (perLine)
            if ((i + 1) % perLine == 0) {
                result += indent;
            }
        }
    }
    return result;
}

void HookTracker::InstallHook(uintptr_t src_addr, HookType type, uintptr_t our_method, const std::string& method_name, const std::vector<HijackedFunction>& hijacked_funcs)
{
    HookRecord record;
    record.address = src_addr;
    record.type = type;
    record.name = method_name;
    record.totalBytesIntercepted = 0;

    // 1. Вычисляем размер изменяемой области для базовой установки хука.
    // Call и Jmp на x86 занимают 5 байт. Подмена слота VTable занимает 4 байта.
    size_t hookSize = (type == HookType::VTable) ? 4 : 5;
    size_t hijacked_bytes_total = 0;

    for (const auto& func : hijacked_funcs) {
        hijacked_bytes_total += func.size;
    }
    record.totalBytesIntercepted = hookSize + hijacked_bytes_total;

    // 2. Читаем и сохраняем оригинальные байты хука для отката в будущем
    record.originalHookBytes.resize(hookSize);
    MemoryEx::ReadMemoryBYTES(src_addr, record.originalHookBytes.data(), hookSize);

    // 3. Записываем команду перехода (устанавливаем хук)
    switch (type)
    {
    case HookType::Call:
        MemoryEx::WriteInstructionCall(src_addr, our_method, 0);
        break;
    case HookType::Jmp:
        MemoryEx::WriteInstructionJmp(src_addr, our_method, 0);
        break;
    case HookType::VTable:
        MemoryEx::WriteMemoryDWORD(src_addr, static_cast<uint32_t>(our_method));
        break;
    }

    // Логируем установку основной точки входа
    Utils::ODS("- [HOOK] %s @ 0x%08X (Total hijacked: %zu bytes)", method_name.c_str(), src_addr, record.totalBytesIntercepted);

    // 4. Обрабатываем и затираем (NOP) оригинальные вызовы функций, которые теперь не нужны
    for (const auto& func : hijacked_funcs)
    {
        if (func.size == 0) continue;

        // Выводим древовидную схему NOP-регионов
        Utils::ODS("  %s- [NOP] %s @ 0x%08X-0x%08X (%zu bytes)",
            &func == &hijacked_funcs.back() ? "\\_" : "|-",
            func.name.c_str(),
            func.start_address,
            func.end_address,
            func.size);

        SavedNop savedNop;
        savedNop.address = func.start_address;
        savedNop.originalBytes.resize(func.size);

        // Безопасно сохраняем затираемые байты оригинального кода
        MemoryEx::ReadMemoryBYTES(func.start_address, savedNop.originalBytes.data(), func.size);

        // Очищаем область памяти инструкциями NOP
        MemoryEx::NOPMemory(func.start_address, func.size);

        record.savedNops.push_back(std::move(savedNop));
    }

    m_totalBytes += record.totalBytesIntercepted;
    m_records.push_back(std::move(record));

    Utils::ODS("[hooked 0x%08X: %zu байт] %s", src_addr, record.totalBytesIntercepted, method_name.c_str());
}

void HookTracker::InstallHook(
    const std::vector<HookTarget>& targets,
    uintptr_t default_method,
    const std::string& method_name,
    const std::vector<HijackedFunction>& hijacked_funcs)
{
    if (targets.empty()) return;

    std::vector<SavedNop> groupSavedNops;
    size_t hijacked_bytes_total = 0;

    // --- 1. Обработка и логирование NOP-регионов (единожды на всю группу хуков) ---
    for (const auto& func : hijacked_funcs)
    {
        if (func.size == 0) continue;

        hijacked_bytes_total += func.size;

        Utils::ODS("  %s- [NOP] %s @ 0x%08X-0x%08X (%zu bytes)",
            &func == &hijacked_funcs.back() ? "\\_" : "|-",
            func.name.c_str(),
            func.start_address,
            func.end_address,
            func.size);

        SavedNop savedNop;
        savedNop.address = func.start_address;
        savedNop.originalBytes.resize(func.size);

        // Сохраняем оригинальные байты и забиваем область NOP-ами
        MemoryEx::ReadMemoryBYTES(func.start_address, savedNop.originalBytes.data(), func.size);
        MemoryEx::NOPMemory(func.start_address, func.size);

        groupSavedNops.push_back(std::move(savedNop));

        // Вычисляем графические символы ветвей для вывода дерева вызовов
        bool isLastFunc = (&func == &hijacked_funcs.back());
        std::string branchSymbol = isLastFunc ? " " : "|";

        // Определяем список адресов вызова (callers)
        std::vector<uintptr_t> callers_to_show = func.callers;
        if (callers_to_show.empty()) {
            for (const auto& t : targets) callers_to_show.push_back(t.address);
        }

        if (!callers_to_show.empty()) {
            // Выводим отформатированное дерево вызовов (по 4 имени на строку)
            std::string formattedCallers = join_resolved_multiline(callers_to_show, branchSymbol, 4);
            Utils::ODS("  %s      (Called from: %s)", branchSymbol.c_str(), formattedCallers.c_str());
        }
    }

    // --- 2. Циклическая установка хуков по списку целей ---
    bool isFirstRecord = true;

    for (const auto& target : targets)
    {
        HookRecord record;
        record.address = target.address;
        record.type = target.type;
        record.name = method_name;

        // Определяем адрес метода-замены (кастомный для цели или глобальный по умолчанию)
        uintptr_t method_to_use = (target.custom_method != 0) ? target.custom_method : default_method;
        size_t hookSize = (target.type == HookType::VTable) ? 4 : 5;

        // NOP-регионы привязываем только к ПЕРВОЙ записи группы, чтобы RestoreAll не восстанавливал их повторно
        if (isFirstRecord) {
            record.totalBytesIntercepted = hookSize + hijacked_bytes_total;
            record.savedNops = std::move(groupSavedNops);
            isFirstRecord = false;
        }
        else {
            record.totalBytesIntercepted = hookSize;
        }

        // Читаем оригинальные байты кода перед изменением
        record.originalHookBytes.resize(hookSize);
        MemoryEx::ReadMemoryBYTES(target.address, record.originalHookBytes.data(), hookSize);

        // Записываем ассемблерную команду перехода в память процесса
        switch (target.type)
        {
        case HookType::Call:
            MemoryEx::WriteInstructionCall(target.address, method_to_use, 0);
            break;
        case HookType::Jmp:
            MemoryEx::WriteInstructionJmp(target.address, method_to_use, 0);
            break;
        case HookType::VTable:
            MemoryEx::WriteMemoryDWORD(target.address, static_cast<uint32_t>(method_to_use));
            break;
        }

        m_totalBytes += record.totalBytesIntercepted;
        m_records.push_back(std::move(record));
    }
}

void HookTracker::RestoreAll()
{
    // Восстанавливаем оригинальное состояние памяти в обратном порядке (LIFO)
    for (auto it = m_records.rbegin(); it != m_records.rend(); ++it)
    {
        // 1. Восстанавливаем за-NOP-ленные ранее участки функций (обратный порядок внутри хука)
        for (auto nopIt = it->savedNops.rbegin(); nopIt != it->savedNops.rend(); ++nopIt)
        {
            MemoryEx::WriteMemoryBYTES(nopIt->address, nopIt->originalBytes.data(), nopIt->originalBytes.size());
        }

        // 2. Восстанавливаем байты самой инструкции перехода хука
        MemoryEx::WriteMemoryBYTES(it->address, it->originalHookBytes.data(), it->originalHookBytes.size());

        Utils::ODS("[unhooked 0x%08X] %s", it->address, it->name.c_str());
    }

    m_records.clear();
    m_totalBytes = 0;
}

void HookTracker::PrintSummary() const
{
    if (m_records.empty()) return;

    size_t total_hijacked_funcs = 0;
    // Суммируем количество всех задействованных NOP-регионов
    for (const auto& record : m_records) {
        total_hijacked_funcs += record.savedNops.size();
    }

    Utils::ODS("==================== Hook Module Summary ====================");
    Utils::ODS("  - Основных точек входа (хуков) установлено: %zu", m_records.size());
    Utils::ODS("  - Дополнительно взято под контроль (NOP) функций: %zu", total_hijacked_funcs);
    Utils::ODS("  - Общий объем перезаписанного кода в клиенте: %zu байт", m_totalBytes);
    Utils::ODS("=============================================================");
}