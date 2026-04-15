#ifndef MINI_ANTIVIRUS_SCANNER_H
#define MINI_ANTIVIRUS_SCANNER_H

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

struct FileInfo {
    std::string name;
    std::filesystem::path path;
    std::uintmax_t size = 0;
};

struct ScanError {
    std::filesystem::path path;
    std::string message;
};

struct ScanResult {
    std::vector<FileInfo> files;
    std::vector<ScanError> errors;
};

class Scanner {
public:
    ScanResult scanDirectory(const std::filesystem::path& root) const;
};

#endif
