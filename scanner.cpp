#include "scanner.h"

#include <system_error>

namespace fs = std::filesystem;

ScanResult Scanner::scanDirectory(const fs::path& root) const {
    ScanResult result;

    std::error_code ec;
    if (!fs::exists(root, ec)) {
        result.errors.push_back({root, ec ? ec.message() : "Target path does not exist"});
        return result;
    }

    if (!fs::is_directory(root, ec)) {
        result.errors.push_back({root, ec ? ec.message() : "Target path is not a directory"});
        return result;
    }

    fs::recursive_directory_iterator iterator(
        root,
        fs::directory_options::skip_permission_denied,
        ec
    );
    fs::recursive_directory_iterator end;

    if (ec) {
        result.errors.push_back({root, "Unable to start traversal: " + ec.message()});
        return result;
    }

    while (iterator != end) {
        const fs::directory_entry entry = *iterator;
        const fs::path currentPath = entry.path();

        bool isRegularFile = entry.is_regular_file(ec);
        if (ec) {
            result.errors.push_back({currentPath, "Metadata error: " + ec.message()});
            ec.clear();
        } else if (isRegularFile) {
            std::uintmax_t fileSize = entry.file_size(ec);
            if (ec) {
                result.errors.push_back({currentPath, "Unable to read file size: " + ec.message()});
                fileSize = 0;
                ec.clear();
            }

            result.files.push_back({currentPath.filename().string(), currentPath, fileSize});
        }

        iterator.increment(ec);
        if (ec) {
            result.errors.push_back({currentPath, "Traversal error: " + ec.message()});
            ec.clear();
        }
    }

    return result;
}
