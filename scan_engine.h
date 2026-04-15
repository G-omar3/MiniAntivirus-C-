#ifndef MINI_ANTIVIRUS_SCAN_ENGINE_H
#define MINI_ANTIVIRUS_SCAN_ENGINE_H

#include "report.h"

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

struct ScanOptions {
    std::filesystem::path projectRoot;
    std::filesystem::path targetDirectory;
    bool quarantineMalware = true;
    bool quarantineSuspect = true;
    bool echoReportToConsole = true;
    std::vector<std::filesystem::path> skippedPaths;
};

struct ScanProgress {
    std::size_t current = 0;
    std::size_t total = 0;
    FileInfo file;
};

struct ScanCallbacks {
    std::function<void(const ScanProgress& progress)> onProgress;
    std::function<bool()> shouldStop;
};

struct ScanOutcome {
    std::vector<ScanRecord> records;
    std::vector<ScanError> traversalErrors;
    ReportSummary summary;
    ReportArtifacts artifacts;
    bool interrupted = false;
    std::string signatureLoadWarning;
};

class MiniAntivirusEngine {
public:
    bool runScan(const ScanOptions& options, const ScanCallbacks& callbacks, ScanOutcome& outcome, std::string& errorMessage) const;
};

#endif
