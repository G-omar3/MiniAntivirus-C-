#ifndef MINI_ANTIVIRUS_REPORT_H
#define MINI_ANTIVIRUS_REPORT_H

#include "scanner.h"
#include "signatures.h"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

enum class ScanStatus {
    Clean,
    Warning,
    Suspect,
    Malware,
    Error
};

struct ScanRecord {
    FileInfo file;
    ScanStatus status = ScanStatus::Clean;
    int score = 0;
    std::string reason;
    std::optional<ThreatInfo> threat;
    std::optional<std::string> hash;
    std::optional<std::filesystem::path> quarantinePath;
};

struct ReportSummary {
    std::size_t total = 0;
    std::size_t clean = 0;
    std::size_t warning = 0;
    std::size_t suspect = 0;
    std::size_t malware = 0;
    std::size_t errors = 0;
    std::size_t quarantined = 0;
};

struct ReportArtifacts {
    std::filesystem::path latestTextReportPath;
    std::filesystem::path latestCsvReportPath;
    std::filesystem::path archiveTextReportPath;
    std::filesystem::path archiveCsvReportPath;
    std::string textReport;
    std::string csvReport;
};

class Reporter {
public:
    explicit Reporter(std::filesystem::path logDirectory);

    bool writeReports(
        const std::filesystem::path& targetDirectory,
        const std::vector<ScanRecord>& records,
        const std::vector<ScanError>& traversalErrors,
        const ReportSummary& summary,
        bool interrupted,
        bool echoToConsole,
        ReportArtifacts& artifacts,
        std::string& errorMessage
    ) const;

    std::vector<std::filesystem::path> listHistoryFiles() const;
    bool readTextFile(const std::filesystem::path& filePath, std::string& contents, std::string& errorMessage) const;
    const std::filesystem::path& logDirectory() const;

private:
    std::filesystem::path logDirectory_;

    static std::string statusToString(ScanStatus status);
    std::string buildTextReport(
        const std::filesystem::path& targetDirectory,
        const std::vector<ScanRecord>& records,
        const std::vector<ScanError>& traversalErrors,
        const ReportSummary& summary,
        bool interrupted
    ) const;
    std::string buildCsvReport(const std::vector<ScanRecord>& records) const;
};

#endif
