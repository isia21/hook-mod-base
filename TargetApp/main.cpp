#include <iostream>
#include <windows.h>
#include <thread>
#include <chrono>

// 1. Интерфейс для тестирования VTable-хука
class IRenderSystem {
public:
    virtual void __thiscall RenderFrame() = 0;
    virtual ~IRenderSystem() {}
};

// 2. Класс, имитирующий подсистему игры
class GameEngine : public IRenderSystem {
public:
    GameEngine() {
        std::cout << "[Engine] Initialized at: " << this << std::endl;
    }

    // Невиртуальный метод (цель для Jmp Hook)
    __declspec(noinline) void UpdateInput() {
        std::cout << "[Engine] Processing original input..." << std::endl;
    }

    // Статический метод (цель для Jmp Hook)
    __declspec(noinline) static void PlayAmbientSound() {
        std::cout << "[Engine] Playing original ambient sound..." << std::endl;
    }

    // Реализация виртуального метода (цель для VTable Hook)
    __declspec(noinline) void __thiscall RenderFrame() override {
        std::cout << "[Engine] Rendering original 3D scene..." << std::endl;
    }
};

// Функция, вызываемая из другого места (цель для Call Hook)
__declspec(noinline) void NetworkTick() {
    std::cout << "[Network] Original network tick executed." << std::endl;
}

// Вызывающая функция (содержит call-site)
__declspec(noinline) void RunNetworkLoop() {
    NetworkTick(); // Здесь компилятор создаст инструкцию CALL (E8)
}

int main() {
    std::cout << "=== TargetApp (Simple Engine Mock) ===" << std::endl;
    std::cout << "PID: " << GetCurrentProcessId() << std::endl;
    std::cout << "======================================" << std::endl;

    // Автозагрузка нашей DLL для удобства отладки
    HMODULE hDll = LoadLibraryA("HookModBase.dll");
    if (hDll) {
        std::cout << "[TargetApp] HookModBase.dll successfully loaded." << std::endl;
    }

    GameEngine* engine = new GameEngine();
    IRenderSystem* render = engine;


    while (true) {
        std::cout << "\n--- [New Frame] ---" << std::endl;

        // 1. Тест Jmp Hook (невиртуальный метод)
        engine->UpdateInput();

        // 2. Тест Jmp Hook (статический метод)
        GameEngine::PlayAmbientSound();

        // 3. Тест VTable Hook (виртуальный метод)
        render->RenderFrame();

        // 4. Тест Call Hook (точка вызова)
        RunNetworkLoop();

        std::this_thread::sleep_for(std::chrono::seconds(3));
    }

    delete engine;
    if (hDll) FreeLibrary(hDll);
    return 0;
}