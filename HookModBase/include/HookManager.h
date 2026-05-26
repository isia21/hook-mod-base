#pragma once
/// <summary>
/// Класс для управления жизненным циклом модулей перехвата (регистрация, инициализация, выгрузка и сбор статистики).
/// </summary>
class HookManager
{
public:
    /// <summary>
    /// Регистрирует новый модуль хуков в системе.
    /// </summary>
    /// <param name="module">Уникальный указатель (std::unique_ptr) на модуль, наследуемый от IHookModule.</param>
    void RegisterModule(std::unique_ptr<IHookModule> module);

    /// <summary>
    /// Последовательно инициализирует все зарегистрированные модули и выводит в ODS общую статистику замещения памяти EXE.
    /// </summary>
    void InitAll();

    /// <summary>
    /// Корректно выгружает все модули в обратном порядке (LIFO) для предотвращения ошибок зависимостей и восстанавливает память.
    /// </summary>
    void ShutdownAll();

private:
    /// <summary>
    /// Контейнер для хранения зарегистрированных модулей.
    /// </summary>
    std::vector<std::unique_ptr<IHookModule>> m_modules;
};