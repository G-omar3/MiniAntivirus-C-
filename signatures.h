#ifndef MINI_ANTIVIRUS_SIGNATURES_H
#define MINI_ANTIVIRUS_SIGNATURES_H

#include <filesystem>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

struct ThreatInfo {
    std::string name;
    std::string severity;
};

class SignatureDatabase {
public:
    bool load(const std::filesystem::path& databasePath, std::string& errorMessage);
    std::optional<ThreatInfo> lookup(const std::string& sha256Hash) const;
    std::size_t size() const;

private:
    std::unordered_map<std::string, std::pair<std::string, std::string>> signatures_;
};

#endif
