#include "scan_engine.h"

#include "hasher.h"
#include "heuristic.h"
#include "quarantine.h"
#include "scanner.h"
#include "signatures.h"

#include <filesystem>
#include <vector>

namespace fs = std::filesystem;

namespace {
std::string joinReasons(const std::vector<std::string>& reasons) {
    if (reasons.empty()) {
        return "no suspicious indicators";
    }

    std::string joined;
    for (std::size_t i = 0; i < reasons.size(); ++i) {
        if (i > 0) {
            joined += ", ";
        }
        joined += reasons[i];
    }
    return joined;
}

void updateSummary(ReportSummary& summary, ScanStatus status, bool quarantined) {
    ++summary.total;
    switch (status) {
    case ScanStatus::Clean:
        ++summary.clean;
        break;
    case ScanStatus::Warning:
        ++summary.warning;
        break;
    case ScanStatus::Suspect:
        ++summary.suspect;
        break;
    case ScanStatus::Malware:
        ++summary.malware;
        break;
    case ScanStatus::Error:
        ++summary.errors;
        break;
    }

    if (quarantined) {
        ++summary.quarantined;
    }
}

bool isWithin(const fs::path& child, const fs::path& parent) {
    std::error_code ec;
    const fs::path normalizedChild = fs::weakly_canonical(child, ec);
    if (ec) {
        return false;
    }

    ec.clear();
    const fs::path normalizedParent = fs::weakly_canonical(parent, ec);
    if (ec) {
        return false;
    }

    auto childIt = normalizedChild.begin();
    auto parentIt = normalizedParent.begin();
    for (; parentIt != normalizedParent.end(); ++parentIt, ++childIt) {
        if (childIt == normalizedChild.end() || *childIt != *parentIt) {
            return false;
        }
    }

    return true;
}

bool shouldSkipPath(const fs::path& path, const ScanOptions& options) {
    for (const auto& skippedPath : options.skippedPaths) {
        if (isWithin(path, skippedPath)) {
            return true;
        }
    }
    return false;
}
}

bool MiniAntivirusEngine::runScan(
    const ScanOptions& options,
    const ScanCallbacks& callbacks,
    ScanOutcome& outcome,
    std::string& errorMessage
) const {
    outcome = ScanOutcome{};

    const fs::path signatureFile = options.projectRoot / "signatures_db.txt";
    const fs::path logDirectory = options.projectRoot / "logs";
    const fs::path quarantineDirectory = options.projectRoot / "quarantine";

    SignatureDatabase signatures;
    std::string signatureMessage;
    if (!signatures.load(signatureFile, signatureMessage)) {
        errorMessage = "Failed to load signatures: " + signatureMessage;
        return false;
    }
    outcome.signatureLoadWarning = signatureMessage;

    Scanner scanner;
    ScanResult scanResult = scanner.scanDirectory(options.targetDirectory);
    if (scanResult.files.empty() && !scanResult.errors.empty()) {
        errorMessage = "Unable to scan target directory";
        outcome.traversalErrors = std::move(scanResult.errors);
        return false;
    }

    std::vector<FileInfo> filteredFiles;
    filteredFiles.reserve(scanResult.files.size());
    for (const auto& file : scanResult.files) {
        if (!shouldSkipPath(file.path, options)) {
            filteredFiles.push_back(file);
        }
    }
    scanResult.files = std::move(filteredFiles);

    Hasher hasher;
    HeuristicEngine heuristicEngine;
    Reporter reporter(logDirectory);
    QuarantineManager quarantine(quarantineDirectory);

    outcome.records.reserve(scanResult.files.size());
    const std::size_t totalFiles = scanResult.files.size();
    for (std::size_t i = 0; i < totalFiles; ++i) {
        if (callbacks.shouldStop && callbacks.shouldStop()) {
            outcome.interrupted = true;
            break;
        }

        const FileInfo& file = scanResult.files[i];
        if (callbacks.onProgress) {
            callbacks.onProgress({i + 1, totalFiles, file});
        }

        ScanRecord record;
        record.file = file;

        std::string hashError;
        const auto hash = hasher.sha256File(file.path, hashError);
        if (!hash) {
            record.status = ScanStatus::Error;
            record.reason = hashError;
            outcome.records.push_back(record);
            updateSummary(outcome.summary, record.status, false);
            continue;
        }

        record.hash = *hash;
        if (const auto threat = signatures.lookup(*hash)) {
            record.status = ScanStatus::Malware;
            record.score = 10;
            record.threat = threat;
            record.reason = "signature match: " + threat->name + " (" + threat->severity + ")";

            if (options.quarantineMalware) {
                std::string quarantineMessage;
                const auto quarantined = quarantine.quarantineFile(file.path, quarantineMessage);
                if (quarantined) {
                    record.quarantinePath = quarantined;
                    record.reason += " | quarantined";
                } else if (!quarantineMessage.empty()) {
                    record.reason += " | quarantine failed: " + quarantineMessage;
                }
            }

            outcome.records.push_back(record);
            updateSummary(outcome.summary, record.status, record.quarantinePath.has_value());
            continue;
        }

        const HeuristicResult heuristics = heuristicEngine.analyze(file);
        record.score = heuristics.score;
        record.reason = joinReasons(heuristics.reasons);

        if (heuristics.classification == "warning") {
            record.status = ScanStatus::Warning;
        } else if (heuristics.classification == "suspect") {
            record.status = ScanStatus::Suspect;
        } else {
            record.status = ScanStatus::Clean;
        }

        if (record.status == ScanStatus::Suspect && options.quarantineSuspect) {
            std::string quarantineMessage;
            const auto quarantined = quarantine.quarantineFile(file.path, quarantineMessage);
            if (quarantined) {
                record.quarantinePath = quarantined;
                record.reason += " | quarantined";
            } else if (!quarantineMessage.empty()) {
                record.reason += " | quarantine failed: " + quarantineMessage;
            }
        }

        outcome.records.push_back(record);
        updateSummary(outcome.summary, record.status, record.quarantinePath.has_value());
    }

    outcome.traversalErrors = std::move(scanResult.errors);
    outcome.summary.errors += outcome.traversalErrors.size();

    if (!reporter.writeReports(
            options.targetDirectory,
            outcome.records,
            outcome.traversalErrors,
            outcome.summary,
            outcome.interrupted,
            options.echoReportToConsole,
            outcome.artifacts,
            errorMessage)) {
        return false;
    }

    errorMessage.clear();
    return true;
}
