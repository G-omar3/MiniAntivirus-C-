#include "signatures.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <vector>

namespace {
std::string trim(const std::string& value) {
    std::size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) {
        ++start;
    }

    std::size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }

    return value.substr(start, end - start);
}

std::string toLower(std::string value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); }
    );
    return value;
}
}

bool SignatureDatabase::load(const std::filesystem::path& databasePath, std::string& errorMessage) {
    signatures_.clear();

    std::ifstream input(databasePath);
    if (!input) {
        errorMessage = "Unable to open signature database: " + databasePath.string();
        return false;
    }

    std::string line;
    std::size_t lineNumber = 0;
    std::size_t malformedLines = 0;
    while (std::getline(input, line)) {
        ++lineNumber;
        const std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#') {
            continue;
        }

        std::stringstream stream(trimmed);
        std::vector<std::string> parts;
        std::string part;
        while (std::getline(stream, part, ';')) {
            parts.push_back(trim(part));
        }

        if (parts.size() != 3 || parts[0].empty()) {
            ++malformedLines;
            continue;
        }

        signatures_[toLower(parts[0])] = {parts[1], parts[2]};
    }

    if (malformedLines > 0) {
        errorMessage = "Loaded with warnings: skipped " + std::to_string(malformedLines) + " malformed line(s)";
    } else {
        errorMessage.clear();
    }

    return true;
}

std::optional<ThreatInfo> SignatureDatabase::lookup(const std::string& sha256Hash) const {
    const auto it = signatures_.find(toLower(sha256Hash));
    if (it == signatures_.end()) {
        return std::nullopt;
    }

    return ThreatInfo{it->second.first, it->second.second};
}

std::size_t SignatureDatabase::size() const {
    return signatures_.size();
}
