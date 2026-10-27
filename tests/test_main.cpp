#include <cstdio>
#include <string>

#include "test_framework.hpp"

namespace tf {

int run_all(const std::string& filter) {
  int passed = 0, failed = 0, ran = 0;
  for (const auto& tc : registry()) {
    std::string full = std::string(tc.suite) + "." + tc.name;
    if (!filter.empty() && full.find(filter) == std::string::npos) continue;
    ++ran;
    failures_here() = 0;
    std::fprintf(stderr, "[ RUN      ] %s\n", full.c_str());
    bool fatal = false;
    tc.fn(fatal);
    if (failures_here() == 0 && !fatal) {
      std::fprintf(stderr, "[       OK ] %s\n", full.c_str());
      ++passed;
    } else {
      std::fprintf(stderr, "[  FAILED  ] %s (%d check(s))\n", full.c_str(), failures_here());
      ++failed;
    }
  }
  std::fprintf(stderr, "\n%d test(s) ran, %d passed, %d failed\n", ran, passed, failed);
  return failed == 0 ? 0 : 1;
}

}  // namespace tf

int main(int argc, char** argv) {
  const std::string filter = argc > 1 ? argv[1] : "";
  return tf::run_all(filter);
}
