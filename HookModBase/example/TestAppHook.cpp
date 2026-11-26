#include "stdafx.h"
#include "TestAppHook.h"
#include "../include/MemoryEx.h"
#include "../include/Utils.h"

#if defined(_WIN64)
#include <cstdio>

/// <summary>Проверяет установку и откат хуков на коде и таблице собственного стенда.</summary>
static bool VerifyDemoHooks(uintptr_t nBaseAddress)
{
	using TDemoFunction = int (*)();
	const uintptr_t nCallEntry = nBaseAddress;
	const uintptr_t nCallAddress = nCallEntry + 4;
	const uintptr_t nJmpAddress = nBaseAddress + 32;
	const uintptr_t nOriginalAddress = nBaseAddress + 64;
	const uintptr_t nReplacementAddress = nBaseAddress + 80;
	const uintptr_t nVtableAddress = nBaseAddress + 96;

	// CALL получает shadow space по соглашению Win64.
	const uint8_t achCall[] = { 0x48, 0x83, 0xEC, 0x28, 0xE8, 0, 0, 0, 0, 0x48, 0x83, 0xC4, 0x28, 0xC3 };
	const uint8_t achOriginal[] = { 0xB8, 1, 0, 0, 0, 0xC3 };
	const uint8_t achReplacement[] = { 0xB8, 2, 0, 0, 0, 0xC3 };
	const uintptr_t anVtable[] = { nOriginalAddress, nOriginalAddress };
	MemoryEx::WriteMemoryBYTES(nCallEntry, achCall, sizeof(achCall));
	MemoryEx::WriteMemoryBYTES(nOriginalAddress, achOriginal, sizeof(achOriginal));
	MemoryEx::WriteMemoryBYTES(nReplacementAddress, achReplacement, sizeof(achReplacement));
	MemoryEx::WriteMemoryBYTES(nVtableAddress, anVtable, sizeof(anVtable));
	MemoryEx::WriteInstructionCall(nCallAddress, nOriginalAddress);
	MemoryEx::WriteInstructionJmp(nJmpAddress, nOriginalAddress);

	auto pfnCall = reinterpret_cast<TDemoFunction>(nCallEntry);
	auto pfnJmp = reinterpret_cast<TDemoFunction>(nJmpAddress);
	const uintptr_t nVtableSlot = nVtableAddress + sizeof(uintptr_t);
	auto CallVtableSlot = [nVtableSlot]() {
		uintptr_t nMethodAddress = 0;
		MemoryEx::ReadMemoryBYTES(nVtableSlot, &nMethodAddress, sizeof(nMethodAddress));
		return reinterpret_cast<TDemoFunction>(nMethodAddress)();
	};
	if (pfnCall() != 1 || pfnJmp() != 1 || CallVtableSlot() != 1) {
		return false;
	}

	HookTracker stTracker;
	const uintptr_t nFarAddress = nJmpAddress > 0x90000000ULL ? 1 : nJmpAddress + 0x90000000ULL;
	bool bRejected = false;
	try {
		stTracker.InstallHook({ { nVtableSlot, HookType::VTable }, { nJmpAddress, HookType::Jmp, nFarAddress } },
			nReplacementAddress, "x64 invalid target");
	}
	catch (const std::invalid_argument&) {
		bRejected = true;
	}
	if (!bRejected || stTracker.GetTotalInterceptedBytes() != 0 || CallVtableSlot() != 1 || pfnJmp() != 1) {
		return false;
	}

	stTracker.InstallHook({ { nCallAddress, HookType::Call }, { nJmpAddress, HookType::Jmp } },
		nReplacementAddress, "x64 branches");
	stTracker.InstallHook(nVtableSlot, HookType::VTable, nReplacementAddress, "x64 VTable");
	const bool bPatched = pfnCall() == 2 && pfnJmp() == 2 && CallVtableSlot() == 2 &&
		stTracker.GetTotalInterceptedBytes() == 10 + sizeof(uintptr_t);
	stTracker.RestoreAll();
	return bPatched && pfnCall() == 1 && pfnJmp() == 1 && CallVtableSlot() == 1;
}

extern "C" __declspec(dllexport) BOOL WINAPI RunHookModBaseDemo()
{
	void* pBuffer = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pBuffer) {
		return FALSE;
	}

	bool bPassed = false;
	try {
		bPassed = VerifyDemoHooks(reinterpret_cast<uintptr_t>(pBuffer));
	}
	catch (const std::exception& stError) {
		std::fprintf(stderr, "[DLL] x64 demo: %s\n", stError.what());
	}
	VirtualFree(pBuffer, 0, MEM_RELEASE);
	return bPassed ? TRUE : FALSE;
}

#else

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

#endif
