#include "stdafx.h"
#include "../include/Utils.h"

/// <summary>
/// Находит размер секций кода (.text) основного исполняемого файла процесса в памяти.
/// Помогает динамически вычислить точный процент замещенного кода без жестких констант.
/// </summary>
/// <returns>Суммарный размер исполняемого кода в байтах или 0 в случае ошибки чтения PE-заголовка.</returns>
static size_t GetExeCodeSize()
{
    // Получаем базовый адрес (HMODULE) текущего процесса (нашего EXE)
    HMODULE hModule = GetModuleHandle(nullptr);
    if (!hModule) return 0;

    // Читаем и проверяем заголовок DOS
    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    // Читаем и проверяем заголовок NT (PE)
    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(hModule) + pDosHeader->e_lfanew
        );
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return 0;

    // Переходим к первой секции таблицы секций
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    size_t totalCodeSize = 0;

    // Проходим по всем секциям PE-файла (.text, .rdata, .data и т.д.)
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++)
    {
        // Суммируем размеры только тех секций, которые содержат исполняемый код (IMAGE_SCN_CNT_CODE)
        if (pSection->Characteristics & IMAGE_SCN_CNT_CODE)
        {
            // VirtualSize указывает на реальный размер кода секции, развернутой в памяти
            totalCodeSize += pSection->Misc.VirtualSize;
        }
    }

    return totalCodeSize;
}

void HookManager::RegisterModule(std::unique_ptr<IHookModule> module)
{
    m_modules.push_back(std::move(module));
}

void HookManager::InitAll()
{
    // 1. Проходим по всем зарегистрированным модулям и инициализируем их
    for (const auto& mod : m_modules)
    {
        if (!mod->Init())
        {
            Utils::ODS("[HookManager] FAILED to initialize module '%s'.\n", mod->GetName());
        }
    }

    // 2. Получаем размер исполняемого кода EXE программно для расчета статистики
    size_t exeCodeSize = GetExeCodeSize();

    // Запасной вариант на случай непредвиденных проблем с парсингом заголовка
    if (exeCodeSize == 0) {
        exeCodeSize = 1024 * 1024 * 5; // По умолчанию принимаем размер за 5 МБ
    }

    // 3. Собираем и выводим детальную статистику замещения памяти
    size_t total_replaced_bytes = 0;

    Utils::ODS("=================== ГЛОБАЛЬНАЯ СТАТИСТИКА ЗАМЕЩЕНИЯ ===================");

    for (const auto& mod : m_modules)
    {
        size_t mod_bytes = mod->GetReplacedBytes();
        total_replaced_bytes += mod_bytes;

        Utils::ODS("[HookManager] Модуль `%-15s`\tЗаменено байт в EXE: %zu", mod->GetName(), mod_bytes);
    }

    // 4. Считаем и выводим процент "захвата" исполняемого файла
    double percentage = (exeCodeSize > 0) ? (static_cast<double>(total_replaced_bytes) / exeCodeSize) * 100.0 : 0.0;

    Utils::ODS("-----------------------------------------------------------------------");
    Utils::ODS("[HookManager] Суммарно заменено байт в EXE: %zu из %zu (%.4f%%)", total_replaced_bytes, exeCodeSize, percentage);
    Utils::ODS("=======================================================================\n");
}

void HookManager::ShutdownAll()
{
    // Выгружаем модули строго в ОБРАТНОМ порядке (LIFO), чтобы избежать проблем 
    // с перекрестными зависимостями модулей во время деинициализации
    for (auto it = m_modules.rbegin(); it != m_modules.rend(); ++it)
    {
        Utils::ODS("[HookManager] Shutting down module '%s'...\n", (*it)->GetName());
        (*it)->Shutdown();
    }
    m_modules.clear();
}