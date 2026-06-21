#pragma once
#include <string>
#include <vector>
#include <initializer_list>

/// <summary>
/// Типы устанавливаемых перехватов (хуков).
/// </summary>
enum class HookType
{
    Call,
    Jmp,
    VTable
};

/// <summary>
/// Описывает конкретную точку установки хука.
/// </summary>
struct HookTarget
{
    /// <summary>Адрес в памяти, куда ставится хук.</summary>
    uintptr_t address;
    /// <summary>Тип хука.</summary>
    HookType type;
    /// <summary>Адрес функции-замены (если 0, используется default_method из InstallHook).</summary>
    uintptr_t custom_method = 0;
};

/// <summary>
/// Описывает оригинальную функцию клиента, которую мы заменяем (через NOP),
/// так как наш хук берет ее функционал на себя.
/// </summary>
struct HijackedFunction
{
    /// <summary>Начальный адрес функции.</summary>
    uintptr_t start_address;
    /// <summary>Конечный адрес функции.</summary>
    uintptr_t end_address;
    /// <summary>Размер функции в байтах.</summary>
    size_t size;
    /// <summary>Имя оригинальной функции для логирования.</summary>
    std::string name;
    /// <summary>Список адресов вызова этой функции.</summary>
    std::vector<uintptr_t> callers;

    /// <summary>
    /// Конструктор для автоматического вычисления размера функции.
    /// </summary>
    /// <param name="start">Начальный адрес функции.</param>
    /// <param name="end">Конечный адрес функции (или точный размер, если end &lt; start).</param>
    /// <param name="func_name">Имя функции для логирования.</param>
    /// <param name="func_callers">Список адресов, откуда она вызывалась.</param>
    HijackedFunction(uintptr_t start, uintptr_t end, std::string func_name, std::initializer_list<uintptr_t> func_callers = {})
        : start_address(start), end_address(end), name(std::move(func_name)), callers(func_callers)
    {
        if (end > start) {
            size = end - start;
        }
        else {
            size = end;
        }
    }
};

/// <summary>
/// Класс для отслеживания установленных хуков и автоматического восстановления памяти.
/// Сохраняет оригинальные байты перед любой модификацией.
/// </summary>
class HookTracker
{
public:

    struct MemoryRange
    {
        uintptr_t address;
        size_t size;
        HookType type;
        bool isNop;
        std::string name;
    };


    void CollectMemoryRanges(std::vector<MemoryRange>& ranges) const;

    /// <summary>
    /// Устанавливает хук и затирает (NOP) связанные с ним оригинальные функции.
    /// </summary>
    /// <param name="src_addr">Адрес в оригинальном коде, куда ставится хук.</param>
    /// <param name="type">Тип хука (Call, Jmp, VTable).</param>
    /// <param name="our_method">Адрес нашей функции-замены.</param>
    /// <param name="method_name">Имя основного хука (для логирования).</param>
    /// <param name="hijacked_funcs">Список оригинальных функций, которые будут за-NOP-лены.</param>
    void InstallHook(uintptr_t src_addr, HookType type, uintptr_t our_method, const std::string& method_name, const std::vector<HijackedFunction>& hijacked_funcs = {});

    /// <summary>
    /// Массово устанавливает хуки и затирает связанные с ними оригинальные функции (выполняет NOP только один раз на группу).
    /// </summary>
    /// <param name="targets">Список точек установки хука {адрес, тип, [кастомный_метод]}.</param>
    /// <param name="default_method">Базовый адрес нашей функции-замены.</param>
    /// <param name="method_name">Имя логической группы хуков (для логирования).</param>
    /// <param name="hijacked_funcs">Список оригинальных функций, которые будут за-NOP-лены.</param>
    void InstallHook(
        const std::vector<HookTarget>& targets,
        uintptr_t default_method,
        const std::string& method_name,
        const std::vector<HijackedFunction>& hijacked_funcs = {}
    );

    /// <summary>
    /// Снимает все установленные хуки и восстанавливает оригинальные байты памяти в обратном порядке (LIFO).
    /// </summary>
    void RestoreAll();

    /// <summary>
    /// Возвращает суммарное количество перехваченных байт данным трекером.
    /// </summary>
    /// <returns>Общее количество измененных байт памяти.</returns>
    size_t GetTotalInterceptedBytes() const { return m_totalBytes; }

    /// <summary>
    /// Выводит в ODS итоговую статистику по перехватам и NOP-регионам данного трекера.
    /// </summary>
    void PrintSummary() const;

private:

    /// <summary>
    /// Внутренняя структура для хранения затертых NOP-ами областей памяти.
    /// </summary>
    struct SavedNop
    {
        uintptr_t address;
        std::vector<uint8_t> originalBytes;
        std::string name;
    };

    /// <summary>
    /// Внутренняя структура для хранения информации об одном установленном хуке.
    /// </summary>
    struct HookRecord
    {
        uintptr_t address;
        HookType type;
        std::string name;
        size_t totalBytesIntercepted;           // Суммарный размер измененных байт (хук + NOP-ы)
        std::vector<uint8_t> originalHookBytes; // Оригинальные байты в месте прыжка/вызова
        std::vector<SavedNop> savedNops;        // Сохраненные оригинальные байты из за-NOP-ленных областей
    };

    std::vector<HookRecord> m_records;
    size_t m_totalBytes = 0;
};

/// <summary>
/// Абстрактный базовый класс (интерфейс) для всех модулей,
/// вносящих изменения в исполняемый файл игры.
/// </summary>
class IHookModule
{
public:
    virtual ~IHookModule() = default;

    /// <summary>
    /// Получает имя модуля для логирования.
    /// </summary>
    /// <returns>Имя модуля в формате C-строки.</returns>
    virtual const char* GetName() const = 0;

    /// <summary>
    /// Выполняется при инициализации модуля. Здесь размещаются хуки и патчи памяти.
    /// </summary>
    /// <returns>True, если инициализация прошла успешно, иначе False.</returns>
    virtual bool Init() = 0;

    /// <summary>
    /// Выполняется при выгрузке модуля. Здесь снимаются хуки и восстанавливаются оригинальные байты.
    /// </summary>
    virtual void Shutdown() = 0;

    /// <summary>
    /// Возвращает количество замененных байт в EXE-файле конкретно этим модулем.
    /// </summary>
    /// <returns>Суммарное количество измененных байт памяти модуля.</returns>
    size_t GetReplacedBytes() const { return m_tracker.GetTotalInterceptedBytes(); }

    void CollectHookMemoryRanges(std::vector<HookTracker::MemoryRange>& ranges) const { m_tracker.CollectMemoryRanges(ranges); }
protected:
    /// <summary>
    /// Встроенный трекер хуков, доступный во всех модулях-наследниках.
    /// </summary>
    HookTracker m_tracker;
};