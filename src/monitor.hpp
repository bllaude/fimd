#pragma once
#include <string>

namespace fimd {

struct CheckOptions {
  std::string baseline;
  std::string pub_key;
  std::string log;  // optional; empty means print only
  bool use_syslog = false;
};

struct WatchOptions : CheckOptions {
  int rescan_secs = 0;     // periodic full rescan, 0 disables
  int debounce_ms = 300;   // quiet period before a burst of events is hashed
};

// One-shot comparison of the live tree against the signed baseline.
// Returns 0 clean, 1 differences found, 2 error.
int run_check(const CheckOptions& opt);

// Long-running inotify monitor. Returns 0 on clean shutdown, 2 on error.
int run_watch(const WatchOptions& opt);

}  // namespace fimd
