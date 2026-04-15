#include "report.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace fs = std::filesystem;

namespace {
std::tm makeLocalTime(std::time_t rawTime) {
    std::tm localTime{};
#ifdef _WIN32
    localtime_s(&localTime, &rawTime);
#else
    localtime_r(&rawTime, &localTime);
#endif
    return localTime;
}

std::string currentTimestamp() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t rawTime = std::chrono::system_clock::to_time_t(now);
    const std::tm localTime = makeLocalTime(rawTime);

    std::ostringstream output;
    output << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S");
    return output.str();
}

std::string currentTimestampForFileName() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t rawTime = std::chrono::system_clock::to_time_t(now);
    const std::tm localTime = makeLocalTime(rawTime);

    std::ostringstream output;
    output << std::put_time(&localTime, "%Y%m%d_%H%M%S");
    return output.str();
}

std::string truncate(const std::string& value, std::size_t width) {
    if (value.size() <= width) {
        return value;
    }

    if (width <= 3) {
        return value.substr(0, width);
    }

    return value.substr(0, width - 3) + "...";
}

std::string csvEscape(const std::string& value) {
    std::string escaped = "\"";
    for (char ch : value) {
        if (ch == '"') {
            escaped += "\"\"";
        } else {
            escaped += ch;
        }
    }
    escaped += "\"";
    return escaped;
}
}

Reporter::Reporter(fs::path logDirectory)
    : logDirectory_(std::move(logDirectory)) {}

std::string Reporter::statusToString(ScanStatus status) {
    switch (status) {
    case ScanStatus::Clean:
        return "CLEAN";
    case ScanStatus::Warning:
        return "WARNING";
    case ScanStatus::Suspect:
        return "SUSPECT";
    case ScanStatus::Malware:
        return "MALWARE";
    case ScanStatus::Error:
        return "ERROR";
    }

    return "UNKNOWN";
}

std::string Reporter::buildTextReport(
    const fs::path& targetDirectory,
    const std::vector<ScanRecord>& records,
    const std::vector<ScanError>& traversalErrors,
    const ReportSummary& summary,
    bool interrupted
) const {
    std::ostringstream report;
    report << "MiniAntivirus Scan Report\n";
    report << "Timestamp: " << currentTimestamp() << '\n';
    report << "Target: " << targetDirectory.string() << '\n';
    report << "Interrupted: " << (interrupted ? "yes" : "no") << "\n\n";

    report << std::left
           << std::setw(10) << "STATUS"
           << std::setw(32) << "FILENAME"
           << std::setw(8) << "SCORE"
           << "REASON\n";
    report << std::string(96, '-') << '\n';

    for (const auto& record : records) {
        report << std::left
               << std::setw(10) << statusToString(record.status)
               << std::setw(32) << truncate(record.file.name, 31)
               << std::setw(8) << record.score
               << record.reason << '\n';
    }

    if (!traversalErrors.empty()) {
        report << "\nTraversal errors:\n";
        for (const auto& error : traversalErrors) {
            report << " - " << error.path.string() << " | " << error.message << '\n';
        }
    }

    report << "\nSummary:\n";
    report << " total=" << summary.total
           << " clean=" << summary.clean
           << " warning=" << summary.warning
           << " suspect=" << summary.suspect
           << " malware=" << summary.malware
           << " errors=" << summary.errors
           << " quarantined=" << summary.quarantined
           << '\n';

    return report.str();
}

std::string Reporter::buildCsvReport(const std::vector<ScanRecord>& records) const {
    std::ostringstream csv;
    csv << "status,path,filename,size_bytes,score,reason,threat_name,severity,sha256,quarantine_path\n";

    for (const auto& record : records) {
        csv << csvEscape(statusToString(record.status)) << ','
            << csvEscape(record.file.path.string()) << ','
            << csvEscape(record.file.name) << ','
            << record.file.size << ','
            << record.score << ','
            << csvEscape(record.reason) << ','
            << csvEscape(record.threat ? record.threat->name : "") << ','
            << csvEscape(record.threat ? record.threat->severity : "") << ','
            << csvEscape(record.hash ? *record.hash : "") << ','
            << csvEscape(record.quarantinePath ? record.quarantinePath->string() : "")
            << '\n';
    }

    return csv.str();
}

bool Reporter::writeReports(
    const fs::path& targetDirectory,
    const std::vector<ScanRecord>& records,
    const std::vector<ScanError>& traversalErrors,
    const ReportSummary& summary,
    bool interrupted,
    bool echoToConsole,
    ReportArtifacts& artifacts,
    std::string& errorMessage
) const {
    std::error_code ec;
    fs::create_directories(logDirectory_, ec);
    if (ec) {
        errorMessage = "Unable to create log directory: " + ec.message();
        return false;
    }

    const std::string fileStamp = currentTimestampForFileName();
    const std::string textReport = buildTextReport(targetDirectory, records, traversalErrors, summary, interrupted);
    const std::string csvReport = buildCsvReport(records);

    artifacts.latestTextReportPath = logDirectory_ / "scan_report.txt";
    artifacts.latestCsvReportPath = logDirectory_ / "scan_report.csv";
    artifacts.archiveTextReportPath = logDirectory_ / ("scan_report_" + fileStamp + ".txt");
    artifacts.archiveCsvReportPath = logDirectory_ / ("scan_report_" + fileStamp + ".csv");
    artifacts.textReport = textReport;
    artifacts.csvReport = csvReport;

    if (echoToConsole) {
        std::cout << textReport;
    }

    std::ofstream textOutput(artifacts.latestTextReportPath, std::ios::trunc);
    if (!textOutput) {
        errorMessage = "Unable to write logs/scan_report.txt";
        return false;
    }
    textOutput << textReport;

    std::ofstream archiveTextOutput(artifacts.archiveTextReportPath, std::ios::trunc);
    if (!archiveTextOutput) {
        errorMessage = "Unable to write timestamped text report";
        return false;
    }
    archiveTextOutput << textReport;

    std::ofstream csvOutput(artifacts.latestCsvReportPath, std::ios::trunc);
    if (!csvOutput) {
        errorMessage = "Unable to write logs/scan_report.csv";
        return false;
    }
    csvOutput << csvReport;

    std::ofstream archiveCsvOutput(artifacts.archiveCsvReportPath, std::ios::trunc);
    if (!archiveCsvOutput) {
        errorMessage = "Unable to write timestamped CSV report";
        return false;
    }
    archiveCsvOutput << csvReport;

    errorMessage.clear();
    return true;
}

std::vector<fs::path> Reporter::listHistoryFiles() const {
    std::vector<fs::path> files;
    std::error_code ec;
    if (!fs::exists(logDirectory_, ec)) {
        return files;
    }

    for (const auto& entry : fs::directory_iterator(logDirectory_, ec)) {
        if (ec) {
            break;
        }

        if (!entry.is_regular_file(ec) || ec) {
            ec.clear();
            continue;
        }

        const std::string name = entry.path().filename().string();
        if (name.rfind("scan_report_", 0) == 0 && entry.path().extension() == ".txt") {
            files.push_back(entry.path());
        }
    }

    std::sort(files.begin(), files.end(), std::greater<fs::path>());
    return files;
}

bool Reporter::readTextFile(const fs::path& filePath, std::string& contents, std::string& errorMessage) const {
    std::ifstream input(filePath);
    if (!input) {
        errorMessage = "Unable to open file: " + filePath.string();
        return false;
    }

    std::ostringstream buffer;
    buffer << input.rdbuf();
    contents = buffer.str();
    errorMessage.clear();
    return true;
}

const fs::path& Reporter::logDirectory() const {
    return logDirectory_;
}
