#pragma once
#include "../include/IHookModule.h"

class TestAppHook : public IHookModule
{
public:
    const char* GetName() const override { return "TestAppHook"; }
    bool Init() override;
    void Shutdown() override;
};