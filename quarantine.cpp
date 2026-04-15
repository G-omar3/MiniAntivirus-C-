#include "quarantine.h"

#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

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

std::string timestampPrefix() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t rawTime = std::chrono::system_clock::to_time_t(now);
    const std::tm localTime = makeLocalTime(rawTime);

    std::ostringstream output;
    output << std::put_time(&localTime, "%Y%m%d_%H%M%S");
    return output.str();
}
}

QuarantineManager::QuarantineManager(fs::path quarantineDirectory)
    : quarantineDirectory_(std::move(quarantineDirectory)),
      indexPath_(quarantineDirectory_ / "index.log") {}

std::optional<fs::path> QuarantineManager::quarantineFile(const fs::path& source, std::string& errorMessage) const {
    std::error_code ec;
    fs::create_directories(quarantineDirectory_, ec);
    if (ec) {
        errorMessage = "Unable to create quarantine directory: " + ec.message();
        return std::nullopt;
    }

    fs::path destination = quarantineDirectory_ / (timestampPrefix() + "_" + source.filename().string());
    int suffix = 1;
    while (fs::exists(destination, ec)) {
        destination = quarantineDirectory_ /
                      (timestampPrefix() + "_" + std::to_string(suffix) + "_" + source.filename().string());
        ++suffix;
    }

    ec.clear();
    fs::copy_file(source, destination, fs::copy_options::overwrite_existing, ec);
    if (ec) {
        errorMessage = "Unable to copy file to quarantine: " + ec.message();
        return std::nullopt;
    }

    std::ofstream index(indexPath_, std::ios::app);
    if (!index) {
        errorMessage = "Quarantine copy completed, but index.log could not be updated";
        return destination;
    }

    index << timestampPrefix() << ';'
          << source.string() << ';'
          << destination.string() << '\n';

    errorMessage.clear();
    return destination;
}

std::vector<QuarantineEntry> QuarantineManager::listEntries(std::string& errorMessage) const {
    std::vector<QuarantineEntry> entries;

    std::ifstream input(indexPath_);
    if (!input) {
        errorMessage = "No quarantine index found yet.";
        return entries;
    }

    std::string line;
    std::size_t index = 1;
    while (std::getline(input, line)) {
        if (line.empty()) {
            continue;
        }

        std::stringstream stream(line);
        std::string timestamp;
        std::string originalPath;
        std::string quarantinePath;

        if (!std::getline(stream, timestamp, ';') ||
            !std::getline(stream, originalPath, ';') ||
            !std::getline(stream, quarantinePath)) {
            continue;
        }

        entries.push_back({index++, timestamp, fs::path(originalPath), fs::path(quarantinePath)});
    }

    errorMessage.clear();
    return entries;
}

bool QuarantineManager::restoreEntry(const QuarantineEntry& entry, std::string& errorMessage) const {
    std::error_code ec;
    fs::create_directories(entry.originalPath.parent_path(), ec);
    if (ec) {
        errorMessage = "Unable to create destination directory: " + ec.message();
        return false;
    }

    fs::copy_file(entry.quarantinePath, entry.originalPath, fs::copy_options::overwrite_existing, ec);
    if (ec) {
        errorMessage = "Unable to restore file: " + ec.message();
        return false;
    }

    errorMessage.clear();
    return true;
}

const fs::path& QuarantineManager::directory() const {
    return quarantineDirectory_;
}
