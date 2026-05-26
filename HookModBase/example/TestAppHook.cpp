#include "stdafx.h"
#include "TestAppHook.h"
#include "../include/MemoryEx.h"
#include "../include/Utils.h"

// =================================================================================
// НАШИ ФУНКЦИИ-ЗАМЕНЫ (ДЕТУРЫ)
// =================================================================================

// 1. Замена для GameEngine::UpdateInput (__thiscall -> __fastcall с пустым EDX)
void __fastcall Hooked_UpdateInput(void* pThis, void* edx)
{
    Utils::ODS("[DLL] [Hooked] UpdateInput! (Instance: %p)", pThis);
    //push message into exe
    printf("[DLL] [Hooked] UpdateInput! (Instance: %p)\n", pThis);
}

// 2. Замена для статического метода GameEngine::PlayAmbientSound (__cdecl)
void __cdecl Hooked_PlayAmbientSound()
{
    Utils::ODS("[DLL] [Hooked] PlayAmbientSound!");
    //push message into exe
    printf("[DLL] [Hooked] PlayAmbientSound\n");
}

// 3. Замена для виртуального метода IRenderSystem::RenderFrame (__thiscall -> __fastcall)
void __fastcall Hooked_RenderFrame(void* pThis, void* edx)
{
    Utils::ODS("[DLL] [Hooked] RenderFrame! Blocking original render.");
    //push message into exe
    printf("[DLL] [Hooked] RenderFrame! Blocking original render. (Instance: %p)\n", pThis);
}

// 4. Замена для Call-хука (вместо NetworkTick)
void __cdecl Hooked_NetworkTick()
{
    Utils::ODS("[DLL] [Hooked] NetworkTick! Custom packet processing.");
    printf("[DLL] [Hooked] NetworkTick! Custom packet processing\n");
}

// =================================================================================
// УСТАНОВКА ХУКОВ
// =================================================================================
bool TestAppHook::Init()
{
    Utils::ODS("[TestAppHook] Initializing simplified hooks...");

    // Рассчитываем адреса динамически на случай ASLR
    uintptr_t exeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));

    // Смещения (RVA), которые вы найдете в IDA для Release x86 версии TargetApp.exe
    uintptr_t rva_UpdateInput = 0x1140;  // Смещение GameEngine::UpdateInput
    uintptr_t rva_PlayAmbientSound = 0x1160;  // Смещение GameEngine::PlayAmbientSound
    uintptr_t rva_VTableSlot = 0x3338;  // Адрес нужного слота в VTable (.rdata)
    uintptr_t rva_CallSite = 0x130D;  // Адрес инструкции E8 внутри main->RunNetworkLoop

    // Применяем хуки, используя безопасные типы uintptr_t

    // 1. Jmp Hook (обычный метод)
    m_tracker.InstallHook(
        exeBase + rva_UpdateInput,
        HookType::Jmp,
        reinterpret_cast<uintptr_t>(Hooked_UpdateInput),
        "GameEngine::UpdateInput"
    );

    // 2. Jmp Hook (статический метод)
    m_tracker.InstallHook(
        exeBase + rva_PlayAmbientSound,
        HookType::Jmp,
        reinterpret_cast<uintptr_t>(Hooked_PlayAmbientSound),
        "GameEngine::PlayAmbientSound"
    );
    
    // 3. VTable Hook (виртуальный метод)
    m_tracker.InstallHook(
        exeBase + rva_VTableSlot,
        HookType::VTable,
        reinterpret_cast<uintptr_t>(Hooked_RenderFrame),
        "IRenderSystem::RenderFrame (VTable)"
    );

    //
    // 4. Call Hook (подмена инструкции call)
    m_tracker.InstallHook(
        exeBase + rva_CallSite,
        HookType::Call,
        reinterpret_cast<uintptr_t>(Hooked_NetworkTick),
        "Main -> RunNetworkLoop (Call Site)"
    );
    
    m_tracker.PrintSummary();
    return true;
}

void TestAppHook::Shutdown()
{
    Utils::ODS("[TestAppHook] Restoring all memory to original state...");
    m_tracker.RestoreAll();
}