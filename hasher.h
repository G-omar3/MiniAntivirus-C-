#ifndef MINI_ANTIVIRUS_HASHER_H
#define MINI_ANTIVIRUS_HASHER_H

#include <filesystem>
#include <optional>
#include <string>

class Hasher {
public:
    std::optional<std::string> sha256File(const std::filesystem::path& path, std::string& errorMessage) const;
};

#endif
