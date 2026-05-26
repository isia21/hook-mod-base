// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "stdafx.h"
#include <thread>
#include "include/SymbolResolver.h"
#include "include/Utils.h"
#include "example/TestAppHook.h" 

// Объявляем глобальный менеджер хуков в том же пространстве имен, как в вашем реальном проекте
HookManager g_HookManager;


// Главный рабочий поток DLL
void MainThread(HMODULE hModule)
{
	// 0. Небольшая задержка для гарантии, что TargetApp полностью загрузится (можно убрать, если уверены в порядке загрузки)
    std::this_thread::sleep_for(std::chrono::seconds(5));

    // 1. Пытаемся загрузить символы (если они есть) для логирования и отладки
    SymbolResolver::Instance().LoadFromFile("ida_exports.txt");

    // 2. Регистрируем наш новый модуль тестирования TargetApp
    g_HookManager.RegisterModule(std::make_unique<TestAppHook>());

    // 3. Инициализируем и устанавливаем все хуки
    g_HookManager.InitAll();

    Utils::ODS("[DLL] All hooks applied. Press [END] to safely exit and restore memory.");

    // 4. Ожидаем нажатия клавиши END для безопасного завершения работы
    while (!(GetAsyncKeyState(VK_END) & 0x8000))
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // 5. Выгружаем все модули (в обратном порядке) и восстанавливаем оригинальную память EXE
    Utils::ODS("[DLL] Shutdown initiated...");
    g_HookManager.ShutdownAll();

    Utils::ODS("[DLL] Memory restored. Unloading library.");

    // Безопасный выход из потока и выгрузка DLL
    FreeLibraryAndExitThread(hModule, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Отключаем вызовы DllMain при создании новых потоков для оптимизации
        DisableThreadLibraryCalls(hModule);

        // Создаем отдельный поток, чтобы не подвешивать инициализацию TargetApp
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, nullptr);
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}