/**
 * main_simple.cpp - SmartAV Entry Point with Advanced UI
 */

#include "UI/MainWindow.h"

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance;
    (void)lpCmdLine;

    AIAntivirus::MainWindow mainWindow;
    
    if (!mainWindow.Initialize(hInstance, nCmdShow)) {
        MessageBoxW(NULL, L"Failed to initialize application", L"SmartAV Error", MB_ICONERROR);
        return 1;
    }

    return mainWindow.Run();
}
