#pragma once
#include <windows.h>
#include <string>

namespace AIAntivirus {

    struct UIConfig {
        bool startMinimized = false;
        bool showNotifications = true;
        std::string language = "ar";
        bool darkMode = true;
    };

    class MainWindow {
    public:
        MainWindow();
        ~MainWindow();

        bool Initialize(HINSTANCE hInstance, int nCmdShow);
        int Run();
        void Shutdown();

        void SetConfig(const UIConfig& config) { m_config = config; }

    private:
        static LRESULT CALLBACK WindowProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
        LRESULT HandleMessage(UINT message, WPARAM wParam, LPARAM lParam);

        bool CreateUI();
        void OnPaint();
        void ResizeControls(int width, int height);

        // Main handles
        HWND m_hWnd = NULL;
        HINSTANCE m_hInstance = NULL;
        UIConfig m_config;
        std::wstring m_customScanPath;
        std::wstring m_currentScanningFile;

        // Control handles for responsive layout
        HWND m_hBtnQuickScan = NULL;
        HWND m_hBtnFullScan = NULL;
        HWND m_hBtnCustomScan = NULL;
        HWND m_hBtnStopScan = NULL;
        HWND m_hStatusText = NULL;
        HWND m_hProgress = NULL;
        HWND m_hScanList = NULL;
        HWND m_hBtnQuarantine = NULL;
        HWND m_hBtnProtection = NULL;
        HWND m_hBtnSettings = NULL;
        HWND m_hBtnUpdate = NULL;
    };

} // namespace AIAntivirus