#ifndef MINI_ANTIVIRUS_HEURISTIC_H
#define MINI_ANTIVIRUS_HEURISTIC_H

#include "scanner.h"

#include <string>
#include <vector>

struct HeuristicResult {
    int score = 0;
    std::vector<std::string> reasons;
    std::string classification = "clean";
    double entropy = 0.0;
};

class HeuristicEngine {
public:
    HeuristicResult analyze(const FileInfo& file) const;
};

#endif
