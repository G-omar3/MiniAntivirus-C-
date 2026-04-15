#ifdef _WIN32

#include "quarantine.h"
#include "report.h"
#include "scan_engine.h"

#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>

#include <atomic>
#include <filesystem>
#include <sstream>
#include <string>
#include <thread>

namespace fs = std::filesystem;

namespace {
constexpr UINT WM_APP_PROGRESS = WM_APP + 1;
constexpr UINT WM_APP_COMPLETE = WM_APP + 2;
constexpr UINT WM_APP_ERROR = WM_APP + 3;

constexpr int IDC_PATH_EDIT = 1001;
constexpr int IDC_BROWSE_BUTTON = 1002;
constexpr int IDC_SCAN_BUTTON = 1003;
constexpr int IDC_STOP_BUTTON = 1004;
constexpr int IDC_HISTORY_BUTTON = 1005;
constexpr int IDC_QUARANTINE_BUTTON = 1006;
constexpr int IDC_OPEN_LOGS_BUTTON = 1007;
constexpr int IDC_PROGRESS_LABEL = 1008;
constexpr int IDC_SUMMARY_LABEL = 1009;
constexpr int IDC_OUTPUT_EDIT = 1010;

struct ProgressPayload {
    std::wstring message;
};

struct CompletionPayload {
    std::wstring summary;
    std::wstring output;
};

struct ErrorPayload {
    std::wstring message;
};

struct AppState {
    fs::path projectRoot;
    HWND window = nullptr;
    HWND pathEdit = nullptr;
    HWND progressLabel = nullptr;
    HWND summaryLabel = nullptr;
    HWND outputEdit = nullptr;
    HWND scanButton = nullptr;
    HWND stopButton = nullptr;
    std::atomic<bool> stopRequested{false};
    bool scanning = false;
    std::thread worker;
};

std::wstring widen(const std::string& input) {
    if (input.empty()) {
        return L"";
    }

    const int needed = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, nullptr, 0);
    if (needed <= 0) {
        return std::wstring(input.begin(), input.end());
    }

    std::wstring output(static_cast<std::size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, &output[0], needed);
    if (!output.empty() && output.back() == L'\0') {
        output.pop_back();
    }
    return output;
}

std::wstring getWindowTextString(HWND handle) {
    const int length = GetWindowTextLengthW(handle);
    std::wstring value(static_cast<std::size_t>(length + 1), L'\0');
    GetWindowTextW(handle, &value[0], length + 1);
    value.resize(static_cast<std::size_t>(length));
    return value;
}

void setOutputText(HWND handle, const std::wstring& text) {
    SetWindowTextW(handle, text.c_str());
}

std::wstring formatHistory(const fs::path& projectRoot) {
    Reporter reporter(projectRoot / "logs");
    const auto history = reporter.listHistoryFiles();

    std::wostringstream output;
    output << L"Archived reports\n\n";
    if (history.empty()) {
        output << L"No archived reports yet.";
        return output.str();
    }

    for (std::size_t i = 0; i < history.size(); ++i) {
        output << (i + 1) << L". " << widen(history[i].filename().string()) << L'\n';
    }

    output << L"\nLatest archived report preview\n\n";
    std::string contents;
    std::string errorMessage;
    if (reporter.readTextFile(history.front(), contents, errorMessage)) {
        output << widen(contents);
    } else {
        output << widen(errorMessage);
    }

    return output.str();
}

std::wstring formatQuarantine(const fs::path& projectRoot) {
    QuarantineManager quarantine(projectRoot / "quarantine");
    std::string errorMessage;
    const auto entries = quarantine.listEntries(errorMessage);

    std::wostringstream output;
    output << L"Quarantine entries\n\n";
    if (!errorMessage.empty() && entries.empty()) {
        output << widen(errorMessage);
        return output.str();
    }

    if (entries.empty()) {
        output << L"Quarantine is empty.";
        return output.str();
    }

    for (const auto& entry : entries) {
        output << entry.index << L". " << widen(entry.timestamp)
               << L"\n   Quarantine: " << widen(entry.quarantinePath.string())
               << L"\n   Original:   " << widen(entry.originalPath.string())
               << L"\n\n";
    }

    return output.str();
}

bool browseForFolder(HWND owner, std::wstring& selectedPath) {
    BROWSEINFOW browseInfo{};
    browseInfo.hwndOwner = owner;
    browseInfo.lpszTitle = L"Select a folder to scan";
    browseInfo.ulFlags = BIF_RETURNONLYFSDIRS | BIF_USENEWUI;

    PIDLIST_ABSOLUTE item = SHBrowseForFolderW(&browseInfo);
    if (!item) {
        return false;
    }

    wchar_t pathBuffer[MAX_PATH];
    const bool success = SHGetPathFromIDListW(item, pathBuffer) == TRUE;
    CoTaskMemFree(item);
    if (!success) {
        return false;
    }

    selectedPath = pathBuffer;
    return true;
}

void setScanningState(AppState* state, bool scanning) {
    state->scanning = scanning;
    EnableWindow(state->scanButton, scanning ? FALSE : TRUE);
    EnableWindow(state->stopButton, scanning ? TRUE : FALSE);
}

void startScan(AppState* state) {
    if (state->scanning) {
        return;
    }

    const std::wstring target = getWindowTextString(state->pathEdit);
    if (target.empty()) {
        MessageBoxW(state->window, L"Please choose a folder to scan.", L"MiniAntivirus", MB_OK | MB_ICONINFORMATION);
        return;
    }

    state->stopRequested.store(false);
    setScanningState(state, true);
    SetWindowTextW(state->progressLabel, L"Preparing scan...");
    SetWindowTextW(state->summaryLabel, L"Summary will appear here.");
    SetWindowTextW(state->outputEdit, L"");

    const fs::path targetPath = fs::path(target);
    state->worker = std::thread([state, targetPath]() {
        MiniAntivirusEngine engine;
        ScanOutcome outcome;
        std::string errorMessage;

        ScanOptions options;
        options.projectRoot = state->projectRoot;
        options.targetDirectory = targetPath;
        options.quarantineMalware = true;
        options.quarantineSuspect = true;
        options.echoReportToConsole = false;
        options.skippedPaths = {state->projectRoot / "logs", state->projectRoot / "quarantine"};

        const bool success = engine.runScan(
            options,
            {
                [state](const ScanProgress& progress) {
                    auto* payload = new ProgressPayload{
                        widen("Scanning [" + std::to_string(progress.current) + "/" +
                              std::to_string(progress.total) + "] " + progress.file.path.string())
                    };
                    PostMessageW(state->window, WM_APP_PROGRESS, 0, reinterpret_cast<LPARAM>(payload));
                },
                [state]() { return state->stopRequested.load(); }
            },
            outcome,
            errorMessage
        );

        if (!success) {
            std::ostringstream message;
            message << errorMessage;
            for (const auto& traversalError : outcome.traversalErrors) {
                message << "\n - " << traversalError.path.string() << " | " << traversalError.message;
            }

            auto* payload = new ErrorPayload{widen(message.str())};
            PostMessageW(state->window, WM_APP_ERROR, 0, reinterpret_cast<LPARAM>(payload));
            return;
        }

        std::ostringstream summary;
        summary << "Total: " << outcome.summary.total
                << "  Clean: " << outcome.summary.clean
                << "  Warning: " << outcome.summary.warning
                << "  Suspect: " << outcome.summary.suspect
                << "  Malware: " << outcome.summary.malware
                << "  Errors: " << outcome.summary.errors
                << "  Quarantined: " << outcome.summary.quarantined;

        auto* payload = new CompletionPayload{widen(summary.str()), widen(outcome.artifacts.textReport)};
        PostMessageW(state->window, WM_APP_COMPLETE, 0, reinterpret_cast<LPARAM>(payload));
    });
}

LRESULT CALLBACK windowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<AppState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (message) {
    case WM_CREATE: {
        auto* createStruct = reinterpret_cast<CREATESTRUCTW*>(lParam);
        state = reinterpret_cast<AppState*>(createStruct->lpCreateParams);
        state->window = hwnd;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));

        CreateWindowW(L"STATIC", L"Folder to scan:", WS_CHILD | WS_VISIBLE,
                      20, 20, 120, 20, hwnd, nullptr, nullptr, nullptr);
        state->pathEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                          20, 45, 520, 28, hwnd, reinterpret_cast<HMENU>(IDC_PATH_EDIT), nullptr, nullptr);
        CreateWindowW(L"BUTTON", L"Browse", WS_CHILD | WS_VISIBLE,
                      550, 45, 100, 28, hwnd, reinterpret_cast<HMENU>(IDC_BROWSE_BUTTON), nullptr, nullptr);
        state->scanButton = CreateWindowW(L"BUTTON", L"Scan", WS_CHILD | WS_VISIBLE,
                                          20, 85, 100, 30, hwnd, reinterpret_cast<HMENU>(IDC_SCAN_BUTTON), nullptr, nullptr);
        state->stopButton = CreateWindowW(L"BUTTON", L"Stop", WS_CHILD | WS_VISIBLE | WS_DISABLED,
                                          130, 85, 100, 30, hwnd, reinterpret_cast<HMENU>(IDC_STOP_BUTTON), nullptr, nullptr);
        CreateWindowW(L"BUTTON", L"History", WS_CHILD | WS_VISIBLE,
                      240, 85, 100, 30, hwnd, reinterpret_cast<HMENU>(IDC_HISTORY_BUTTON), nullptr, nullptr);
        CreateWindowW(L"BUTTON", L"Quarantine", WS_CHILD | WS_VISIBLE,
                      350, 85, 120, 30, hwnd, reinterpret_cast<HMENU>(IDC_QUARANTINE_BUTTON), nullptr, nullptr);
        CreateWindowW(L"BUTTON", L"Open Logs", WS_CHILD | WS_VISIBLE,
                      480, 85, 120, 30, hwnd, reinterpret_cast<HMENU>(IDC_OPEN_LOGS_BUTTON), nullptr, nullptr);

        state->progressLabel = CreateWindowW(L"STATIC", L"Progress will appear here.", WS_CHILD | WS_VISIBLE,
                                             20, 130, 740, 20, hwnd, reinterpret_cast<HMENU>(IDC_PROGRESS_LABEL), nullptr, nullptr);
        state->summaryLabel = CreateWindowW(L"STATIC", L"Summary will appear here.", WS_CHILD | WS_VISIBLE,
                                            20, 155, 740, 20, hwnd, reinterpret_cast<HMENU>(IDC_SUMMARY_LABEL), nullptr, nullptr);
        state->outputEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            L"EDIT",
            L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            20,
            185,
            740,
            330,
            hwnd,
            reinterpret_cast<HMENU>(IDC_OUTPUT_EDIT),
            nullptr,
            nullptr
        );
        return 0;
    }
    case WM_COMMAND:
        if (!state) {
            break;
        }
        switch (LOWORD(wParam)) {
        case IDC_BROWSE_BUTTON: {
            std::wstring selectedPath;
            if (browseForFolder(hwnd, selectedPath)) {
                SetWindowTextW(state->pathEdit, selectedPath.c_str());
            }
            return 0;
        }
        case IDC_SCAN_BUTTON:
            startScan(state);
            return 0;
        case IDC_STOP_BUTTON:
            state->stopRequested.store(true);
            SetWindowTextW(state->progressLabel, L"Stop requested. Waiting for current file...");
            return 0;
        case IDC_HISTORY_BUTTON:
            setOutputText(state->outputEdit, formatHistory(state->projectRoot));
            return 0;
        case IDC_QUARANTINE_BUTTON:
            setOutputText(state->outputEdit, formatQuarantine(state->projectRoot));
            return 0;
        case IDC_OPEN_LOGS_BUTTON:
            ShellExecuteW(hwnd, L"open", widen((state->projectRoot / "logs").string()).c_str(), nullptr, nullptr, SW_SHOWDEFAULT);
            return 0;
        default:
            break;
        }
        break;
    case WM_APP_PROGRESS: {
        auto* payload = reinterpret_cast<ProgressPayload*>(lParam);
        if (state && payload) {
            SetWindowTextW(state->progressLabel, payload->message.c_str());
        }
        delete payload;
        return 0;
    }
    case WM_APP_COMPLETE: {
        auto* payload = reinterpret_cast<CompletionPayload*>(lParam);
        if (state && payload) {
            setScanningState(state, false);
            if (state->worker.joinable()) {
                state->worker.join();
            }
            SetWindowTextW(state->progressLabel, L"Scan completed.");
            SetWindowTextW(state->summaryLabel, payload->summary.c_str());
            SetWindowTextW(state->outputEdit, payload->output.c_str());
        }
        delete payload;
        return 0;
    }
    case WM_APP_ERROR: {
        auto* payload = reinterpret_cast<ErrorPayload*>(lParam);
        if (state && payload) {
            setScanningState(state, false);
            if (state->worker.joinable()) {
                state->worker.join();
            }
            SetWindowTextW(state->progressLabel, L"Scan failed.");
            SetWindowTextW(state->summaryLabel, L"No summary available.");
            SetWindowTextW(state->outputEdit, payload->message.c_str());
        }
        delete payload;
        return 0;
    }
    case WM_DESTROY:
        if (state) {
            state->stopRequested.store(true);
            if (state->worker.joinable()) {
                state->worker.join();
            }
        }
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }

    return DefWindowProcW(hwnd, message, wParam, lParam);
}
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE, LPSTR, int showCommand) {
    AppState state;
    state.projectRoot = fs::current_path();

    const wchar_t* className = L"MiniAntivirusWindow";
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = windowProc;
    windowClass.hInstance = instance;
    windowClass.lpszClassName = className;
    windowClass.hCursor = LoadCursor(nullptr, IDC_ARROW);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);

    if (!RegisterClassW(&windowClass)) {
        MessageBoxW(nullptr, L"Unable to register GUI window class.", L"MiniAntivirus", MB_OK | MB_ICONERROR);
        return 1;
    }

    HWND window = CreateWindowW(
        className,
        L"MiniAntivirus GUI",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        800,
        580,
        nullptr,
        nullptr,
        instance,
        &state
    );

    if (!window) {
        MessageBoxW(nullptr, L"Unable to create GUI window.", L"MiniAntivirus", MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(window, showCommand);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return static_cast<int>(msg.wParam);
}

#endif
