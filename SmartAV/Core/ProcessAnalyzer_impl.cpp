/**
 * ProcessAnalyzer_impl.cpp - Process Analyzer Implementation
 */

#include "ProcessAnalyzer.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <filesystem>

#pragma comment(lib, "psapi.lib")

namespace fs = std::filesystem;

namespace AIAntivirus {

    ProcessAnalyzer& ProcessAnalyzer::GetInstance() {
        static ProcessAnalyzer instance;
        return instance;
    }

    bool ProcessAnalyzer::Initialize(const AnalyzerConfig& config) {
        m_config = config;
        m_isInitialized = true;
        return true;
    }

    void ProcessAnalyzer::Shutdown() {
        m_isInitialized = false;
    }

    ProcessAnalysisReport ProcessAnalyzer::AnalyzeProcess(DWORD processId) {
        ProcessAnalysisReport report;
        report.processId = processId;
        report.startTime = std::chrono::system_clock::now();
        report.threatScore = 0.0f;
        report.isMalicious = false;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) {
            report.indicators.push_back("Failed to open process");
            return report;
        }

        // Get process name
        wchar_t processPath[MAX_PATH];
        if (GetModuleFileNameExW(hProcess, NULL, processPath, MAX_PATH)) {
            report.executablePath = processPath;
            report.processName = fs::path(processPath).filename().wstring();
        }

        // Get loaded modules
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                ModuleInfo modInfo;
                wchar_t modName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], modName, MAX_PATH)) {
                    modInfo.fullPath = modName;
                    modInfo.name = fs::path(modName).filename().wstring();
                }
                MODULEINFO mi;
                if (GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi))) {
                    modInfo.baseAddress = mi.lpBaseOfDll;
                    modInfo.size = mi.SizeOfImage;
                }
                report.loadedModules.push_back(modInfo);
            }
        }

        CloseHandle(hProcess);

        // Simple risk assessment
        if (report.loadedModules.size() > 100) {
            report.threatScore += 0.2f;
            report.indicators.push_back("Large number of loaded modules");
        }

        report.isMalicious = report.threatScore >= 0.7f;
        return report;
    }

    std::vector<ProcessAnalysisReport> ProcessAnalyzer::AnalyzeAllProcesses() {
        std::vector<ProcessAnalysisReport> reports;

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return reports;

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(pe32);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID != 0) {
                    auto report = AnalyzeProcess(pe32.th32ProcessID);
                    reports.push_back(report);
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return reports;
    }

    bool ProcessAnalyzer::IsProcessSuspicious(DWORD processId, float* riskScore) {
        auto report = AnalyzeProcess(processId);
        if (riskScore) *riskScore = report.threatScore;
        return report.isMalicious;
    }

    bool ProcessAnalyzer::TerminateProcess(DWORD processId) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
        if (!hProcess) return false;
        
        BOOL result = ::TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        return result == TRUE;
    }

} // namespace AIAntivirus
