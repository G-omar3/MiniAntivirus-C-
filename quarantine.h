#ifndef MINI_ANTIVIRUS_QUARANTINE_H
#define MINI_ANTIVIRUS_QUARANTINE_H

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

struct QuarantineEntry {
    std::size_t index = 0;
    std::string timestamp;
    std::filesystem::path originalPath;
    std::filesystem::path quarantinePath;
};

class QuarantineManager {
public:
    explicit QuarantineManager(std::filesystem::path quarantineDirectory);
    std::optional<std::filesystem::path> quarantineFile(const std::filesystem::path& source, std::string& errorMessage) const;
    std::vector<QuarantineEntry> listEntries(std::string& errorMessage) const;
    bool restoreEntry(const QuarantineEntry& entry, std::string& errorMessage) const;
    const std::filesystem::path& directory() const;

private:
    std::filesystem::path quarantineDirectory_;
    std::filesystem::path indexPath_;
};

#endif
