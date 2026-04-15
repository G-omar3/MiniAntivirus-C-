#include "interactive_cli.h"
#include "scan_engine.h"

#include <atomic>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <string>

namespace fs = std::filesystem;

namespace {
std::atomic<bool> g_stopRequested{false};

void handleSignal(int) {
    g_stopRequested.store(true);
}

std::string usageText() {
    return "Usage:\n"
           "  MiniAntivirus <directory_to_scan>\n"
           "  MiniAntivirus --interactive\n"
           "  MiniAntivirus --help\n";
}
}

int main(int argc, char* argv[]) {
    const fs::path projectRoot = fs::current_path();

    if (argc == 1) {
        return runInteractiveCli(projectRoot);
    }

    const std::string command = argv[1];
    if (command == "--interactive") {
        return runInteractiveCli(projectRoot);
    }

    if (command == "--help" || command == "-h") {
        std::cout << usageText();
        return 0;
    }

    std::signal(SIGINT, handleSignal);
    g_stopRequested.store(false);

    MiniAntivirusEngine engine;
    ScanOutcome outcome;
    std::string errorMessage;

    ScanOptions options;
    options.projectRoot = projectRoot;
    options.targetDirectory = fs::path(argv[1]);
    options.quarantineMalware = true;
    options.quarantineSuspect = true;
    options.echoReportToConsole = true;
    options.skippedPaths = {projectRoot / "logs", projectRoot / "quarantine"};

    const bool success = engine.runScan(
        options,
        {
            [](const ScanProgress& progress) {
                std::cout << '\r'
                          << "[" << progress.current << "/" << progress.total << "] "
                          << "Scanning " << progress.file.path.string()
                          << std::string(12, ' ')
                          << std::flush;
            },
            []() { return g_stopRequested.load(); }
        },
        outcome,
        errorMessage
    );

    std::cout << '\n';
    if (!outcome.signatureLoadWarning.empty()) {
        std::cerr << "Signature database warning: " << outcome.signatureLoadWarning << '\n';
    }

    if (!success) {
        std::cerr << errorMessage << '\n';
        for (const auto& traversalError : outcome.traversalErrors) {
            std::cerr << " - " << traversalError.path.string() << " | " << traversalError.message << '\n';
        }
        return 1;
    }

    std::cout << "\nReports written to " << outcome.artifacts.latestTextReportPath << " and "
              << outcome.artifacts.latestCsvReportPath << '\n';
    return 0;
}
