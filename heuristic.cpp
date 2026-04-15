#include "heuristic.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <unordered_set>

namespace fs = std::filesystem;

namespace {
constexpr std::size_t kHeuristicReadLimit = 512 * 1024;
constexpr std::uintmax_t kOneKilobyte = 1024;
constexpr std::uintmax_t kFiftyMegabytes = 50ULL * 1024ULL * 1024ULL;

const std::unordered_set<std::string> kRiskyExtensions = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr"
};

const std::array<const char*, 6> kSuspiciousKeywords = {
    "powershell",
    "virtualalloc",
    "createremotethread",
    "base64",
    "startup",
    "registry"
};

const std::array<const char*, 11> kDocumentKeywords = {
    "invoice",
    "report",
    "statement",
    "scan",
    "document",
    "resume",
    "photo",
    "image",
    "img",
    "pdf",
    "doc"
};

std::string toLower(std::string value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); }
    );
    return value;
}

bool isRiskyExtension(const fs::path& path) {
    return kRiskyExtensions.count(toLower(path.extension().string())) > 0;
}

bool hasDoubleExtension(const fs::path& path) {
    const std::string fileName = toLower(path.filename().string());
    const std::size_t firstDot = fileName.find('.');
    const std::size_t lastDot = fileName.rfind('.');
    return firstDot != std::string::npos && firstDot != lastDot && isRiskyExtension(path);
}

std::vector<unsigned char> readFileSample(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return {};
    }

    std::vector<unsigned char> data;
    data.reserve(kHeuristicReadLimit);

    std::array<char, 4096> buffer{};
    while (input.good() && data.size() < kHeuristicReadLimit) {
        const std::size_t remaining = kHeuristicReadLimit - data.size();
        const std::streamsize chunkSize = static_cast<std::streamsize>(
            std::min<std::size_t>(buffer.size(), remaining)
        );

        input.read(buffer.data(), chunkSize);
        const std::streamsize bytesRead = input.gcount();
        if (bytesRead <= 0) {
            break;
        }

        data.insert(data.end(), buffer.begin(), buffer.begin() + bytesRead);
    }

    return data;
}

bool containsSuspiciousKeyword(const std::vector<unsigned char>& data) {
    if (data.empty()) {
        return false;
    }

    std::string content(data.begin(), data.end());
    content = toLower(content);

    for (const char* keyword : kSuspiciousKeywords) {
        if (content.find(keyword) != std::string::npos) {
            return true;
        }
    }

    return false;
}

double calculateEntropy(const std::vector<unsigned char>& data) {
    if (data.empty()) {
        return 0.0;
    }

    std::array<std::size_t, 256> frequencies{};
    for (unsigned char byte : data) {
        ++frequencies[byte];
    }

    double entropy = 0.0;
    const double size = static_cast<double>(data.size());
    for (std::size_t count : frequencies) {
        if (count == 0) {
            continue;
        }

        const double probability = static_cast<double>(count) / size;
        entropy -= probability * std::log2(probability);
    }

    return entropy;
}

bool hasNameExtensionMismatch(const fs::path& path) {
    if (!isRiskyExtension(path)) {
        return false;
    }

    const std::string stem = toLower(path.stem().string());
    for (const char* keyword : kDocumentKeywords) {
        if (stem.find(keyword) != std::string::npos) {
            return true;
        }
    }

    return false;
}
}

HeuristicResult HeuristicEngine::analyze(const FileInfo& file) const {
    HeuristicResult result;
    const bool riskyExtension = isRiskyExtension(file.path);

    if (riskyExtension) {
        result.score += 2;
        result.reasons.push_back("risky extension");
    }

    if (hasDoubleExtension(file.path)) {
        result.score += 3;
        result.reasons.push_back("double extension");
    }

    const std::vector<unsigned char> sample = readFileSample(file.path);
    if (containsSuspiciousKeyword(sample)) {
        result.score += 2;
        result.reasons.push_back("suspicious keywords in content");
    }

    if (riskyExtension && (file.size < kOneKilobyte || file.size > kFiftyMegabytes)) {
        result.score += 1;
        result.reasons.push_back("abnormal executable size");
    }

    result.entropy = calculateEntropy(sample);
    if (result.entropy > 7.2) {
        result.score += 2;
        result.reasons.push_back("high byte entropy");
    }

    if (hasNameExtensionMismatch(file.path)) {
        result.score += 2;
        result.reasons.push_back("name/extension mismatch");
    }

    if (result.score <= 1) {
        result.classification = "clean";
    } else if (result.score <= 3) {
        result.classification = "warning";
    } else {
        result.classification = "suspect";
    }

    return result;
}
