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

        HWND m_hWnd = NULL;
        HINSTANCE m_hInstance = NULL;
        UIConfig m_config;
    };

} // namespace AIAntivirus