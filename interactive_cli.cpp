#include "interactive_cli.h"

#include "quarantine.h"
#include "report.h"
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

std::string promptLine(const std::string& prompt) {
    std::cout << prompt;
    std::string value;
    std::getline(std::cin, value);
    return value;
}

void showHistory(const Reporter& reporter) {
    const auto history = reporter.listHistoryFiles();
    if (history.empty()) {
        std::cout << "No archived reports yet.\n";
        return;
    }

    std::cout << "\nArchived reports:\n";
    for (std::size_t i = 0; i < history.size(); ++i) {
        std::cout << " " << (i + 1) << ". " << history[i].filename().string() << '\n';
    }

    const std::string choice = promptLine("Open which report number? (Enter to cancel): ");
    if (choice.empty()) {
        return;
    }

    std::size_t index = 0;
    try {
        index = static_cast<std::size_t>(std::stoul(choice));
    } catch (...) {
        std::cout << "Invalid choice.\n";
        return;
    }

    if (index == 0 || index > history.size()) {
        std::cout << "Choice out of range.\n";
        return;
    }

    std::string contents;
    std::string errorMessage;
    if (!reporter.readTextFile(history[index - 1], contents, errorMessage)) {
        std::cout << errorMessage << '\n';
        return;
    }

    std::cout << '\n' << contents << '\n';
}

void showQuarantine(const QuarantineManager& quarantine) {
    std::string errorMessage;
    const auto entries = quarantine.listEntries(errorMessage);
    if (!errorMessage.empty()) {
        std::cout << errorMessage << '\n';
    }

    if (entries.empty()) {
        return;
    }

    std::cout << "\nQuarantine entries:\n";
    for (const auto& entry : entries) {
        std::cout << " " << entry.index << ". "
                  << entry.timestamp << " | "
                  << entry.quarantinePath.filename().string()
                  << "\n    original: " << entry.originalPath.string()
                  << '\n';
    }
}

void restoreFromQuarantine(const QuarantineManager& quarantine) {
    std::string errorMessage;
    const auto entries = quarantine.listEntries(errorMessage);
    if (!errorMessage.empty()) {
        std::cout << errorMessage << '\n';
    }

    if (entries.empty()) {
        return;
    }

    for (const auto& entry : entries) {
        std::cout << " " << entry.index << ". "
                  << entry.quarantinePath.filename().string()
                  << " -> " << entry.originalPath.string() << '\n';
    }

    const std::string choice = promptLine("Restore which entry number? (Enter to cancel): ");
    if (choice.empty()) {
        return;
    }

    std::size_t targetIndex = 0;
    try {
        targetIndex = static_cast<std::size_t>(std::stoul(choice));
    } catch (...) {
        std::cout << "Invalid choice.\n";
        return;
    }

    for (const auto& entry : entries) {
        if (entry.index == targetIndex) {
            if (quarantine.restoreEntry(entry, errorMessage)) {
                std::cout << "Restored to " << entry.originalPath.string() << '\n';
            } else {
                std::cout << errorMessage << '\n';
            }
            return;
        }
    }

    std::cout << "Entry not found.\n";
}

int runInteractiveScan(const fs::path& projectRoot) {
    const std::string targetInput = promptLine("Directory to scan: ");
    if (targetInput.empty()) {
        std::cout << "No directory provided.\n";
        return 0;
    }

    const std::string quarantineSuspectChoice = promptLine("Quarantine suspect files? (y/n, default y): ");
    const bool quarantineSuspect =
        quarantineSuspectChoice.empty() ||
        quarantineSuspectChoice == "y" ||
        quarantineSuspectChoice == "Y";

    std::signal(SIGINT, handleSignal);
    g_stopRequested.store(false);

    MiniAntivirusEngine engine;
    ScanOutcome outcome;
    std::string errorMessage;

    ScanOptions options;
    options.projectRoot = projectRoot;
    options.targetDirectory = fs::path(targetInput);
    options.quarantineMalware = true;
    options.quarantineSuspect = quarantineSuspect;
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
        std::cout << "Signature database warning: " << outcome.signatureLoadWarning << '\n';
    }

    if (!success) {
        std::cout << errorMessage << '\n';
        for (const auto& traversalError : outcome.traversalErrors) {
            std::cout << " - " << traversalError.path.string() << " | " << traversalError.message << '\n';
        }
        return 1;
    }

    std::cout << "\nReports saved to:\n"
              << " - " << outcome.artifacts.latestTextReportPath.string() << '\n'
              << " - " << outcome.artifacts.latestCsvReportPath.string() << '\n';
    return 0;
}
}

int runInteractiveCli(const fs::path& projectRoot) {
    Reporter reporter(projectRoot / "logs");
    QuarantineManager quarantine(projectRoot / "quarantine");

    while (true) {
        std::cout << "\nMiniAntivirus Interactive Menu\n"
                  << " 1. Scan a directory\n"
                  << " 2. Show report history\n"
                  << " 3. View quarantine\n"
                  << " 4. Restore quarantined file\n"
                  << " 5. Exit\n"
                  << "Choice: ";

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "1") {
            runInteractiveScan(projectRoot);
        } else if (choice == "2") {
            showHistory(reporter);
        } else if (choice == "3") {
            showQuarantine(quarantine);
        } else if (choice == "4") {
            restoreFromQuarantine(quarantine);
        } else if (choice == "5" || std::cin.eof()) {
            return 0;
        } else {
            std::cout << "Unknown choice.\n";
        }
    }
}
