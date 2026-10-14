#include <sys/stat.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "baseline.hpp"
#include "chainlog.hpp"
#include "crypto.hpp"
#include "monitor.hpp"
#include "util.hpp"

using namespace fimd;

namespace {

const char* kUsage =
    "fimd - file integrity monitor with signed baseline and hash-chained log\n"
    "\n"
    "  fimd keygen     --priv FILE --pub FILE\n"
    "  fimd init       -w DIR [-w DIR ...] [-x PATH ...] --baseline FILE --key PRIVKEY\n"
    "  fimd check      --baseline FILE --pub PUBKEY [--log FILE] [--syslog]\n"
    "  fimd watch      --baseline FILE --pub PUBKEY --log FILE [--syslog]\n"
    "                  [--rescan SECONDS] [--debounce MS]\n"
    "  fimd verify-log --log FILE [--expect-head HEX] [--expect-count N]\n"
    "  fimd head       --log FILE\n"
    "\n"
    "The private key is only needed by keygen and init; keep it off the monitored host.\n"
    "check exits 0 when clean, 1 on differences, 2 on error.\n";

struct Args {
  std::map<std::string, std::vector<std::string>> opts;
  std::set<std::string> flags;
  bool ok = true;

  bool has(const std::string& k) const { return opts.count(k) || flags.count(k); }
  std::string get(const std::string& k) const {
    auto it = opts.find(k);
    return it == opts.end() || it->second.empty() ? std::string() : it->second.back();
  }
  const std::vector<std::string>& all(const std::string& k) const {
    static const std::vector<std::string> none;
    auto it = opts.find(k);
    return it == opts.end() ? none : it->second;
  }
};

Args parse_args(int argc, char** argv, int first) {
  static const std::map<std::string, std::string> alias = {{"-w", "--watch"}, {"-x", "--exclude"}};
  static const std::set<std::string> valued = {"--watch", "--exclude", "--baseline", "--key", "--priv",
                                               "--pub", "--log", "--rescan", "--debounce",
                                               "--expect-head", "--expect-count"};
  static const std::set<std::string> boolean = {"--syslog"};
  Args a;
  for (int i = first; i < argc; ++i) {
    std::string k = argv[i];
    auto al = alias.find(k);
    if (al != alias.end()) k = al->second;
    if (valued.count(k)) {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "fimd: %s needs a value\n", argv[i]);
        a.ok = false;
        return a;
      }
      a.opts[k].push_back(argv[++i]);
    } else if (boolean.count(k)) {
      a.flags.insert(k);
    } else {
      std::fprintf(stderr, "fimd: unknown option %s\n", argv[i]);
      a.ok = false;
      return a;
    }
  }
  return a;
}

bool require(const Args& a, std::initializer_list<const char*> keys) {
  bool ok = true;
  for (const char* k : keys) {
    if (!a.has(k)) {
      std::fprintf(stderr, "fimd: missing %s\n", k);
      ok = false;
    }
  }
  return ok;
}

bool parse_int(const std::string& s, int lo, int hi, int& out) {
  char* end = nullptr;
  long v = std::strtol(s.c_str(), &end, 10);
  if (s.empty() || *end || v < lo || v > hi) return false;
  out = static_cast<int>(v);
  return true;
}

int cmd_keygen(const Args& a) {
  if (!require(a, {"--priv", "--pub"})) return 2;
  std::string err;
  if (!generate_keypair(a.get("--priv"), a.get("--pub"), err)) {
    std::fprintf(stderr, "fimd: %s\n", err.c_str());
    return 2;
  }
  std::fprintf(stderr, "fimd: wrote %s (0600) and %s\n", a.get("--priv").c_str(), a.get("--pub").c_str());
  return 0;
}

int cmd_init(const Args& a) {
  if (!require(a, {"--watch", "--baseline", "--key"})) return 2;
  Baseline b;
  for (const auto& r : a.all("--watch")) {
    std::string root = normalize_path(r);
    struct stat st;
    if (::stat(root.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
      std::fprintf(stderr, "fimd: %s is not a directory\n", root.c_str());
      return 2;
    }
    b.scope.roots.push_back(root);
  }
  for (const auto& x : a.all("--exclude")) b.scope.excludes.push_back(normalize_path(x));
  // The baseline and its signature must never be hashed into themselves.
  b.scope.excludes.push_back(normalize_path(a.get("--baseline")));
  b.scope.excludes.push_back(normalize_path(a.get("--baseline")) + ".sig");
  if (a.has("--log")) b.scope.excludes.push_back(normalize_path(a.get("--log")));

  b.created = utc_now();
  b.entries = scan(b.scope);
  std::string err;
  if (!save_signed(b, a.get("--baseline"), a.get("--key"), err)) {
    std::fprintf(stderr, "fimd: %s\n", err.c_str());
    return 2;
  }
  std::fprintf(stderr, "fimd: baseline of %zu files written to %s (+ .sig)\n", b.entries.size(),
               a.get("--baseline").c_str());
  return 0;
}

int cmd_check(const Args& a) {
  if (!require(a, {"--baseline", "--pub"})) return 2;
  CheckOptions o;
  o.baseline = a.get("--baseline");
  o.pub_key = a.get("--pub");
  o.log = a.get("--log");
  o.use_syslog = a.has("--syslog");
  return run_check(o);
}

int cmd_watch(const Args& a) {
  if (!require(a, {"--baseline", "--pub", "--log"})) return 2;
  WatchOptions o;
  o.baseline = a.get("--baseline");
  o.pub_key = a.get("--pub");
  o.log = a.get("--log");
  o.use_syslog = a.has("--syslog");
  if (a.has("--rescan") && !parse_int(a.get("--rescan"), 0, 86400 * 7, o.rescan_secs)) {
    std::fprintf(stderr, "fimd: --rescan must be 0..604800 seconds\n");
    return 2;
  }
  if (a.has("--debounce") && !parse_int(a.get("--debounce"), 10, 10000, o.debounce_ms)) {
    std::fprintf(stderr, "fimd: --debounce must be 10..10000 ms\n");
    return 2;
  }
  return run_watch(o);
}

int cmd_verify_log(const Args& a) {
  if (!require(a, {"--log"})) return 2;
  std::string head, err;
  uint64_t count = 0;
  if (!ChainLog::verify(a.get("--log"), head, count, err)) {
    std::fprintf(stderr, "fimd: CHAIN BROKEN: %s\n", err.c_str());
    return 1;
  }
  if (a.has("--expect-head") && a.get("--expect-head") != head) {
    std::fprintf(stderr, "fimd: chain is internally consistent but head %s differs from expected %s\n",
                 head.c_str(), a.get("--expect-head").c_str());
    return 1;
  }
  if (a.has("--expect-count") && a.get("--expect-count") != std::to_string(count)) {
    std::fprintf(stderr, "fimd: chain has %llu records, expected %s (tail truncated or extended?)\n",
                 static_cast<unsigned long long>(count), a.get("--expect-count").c_str());
    return 1;
  }
  std::printf("OK records=%llu head=%s\n", static_cast<unsigned long long>(count), head.c_str());
  return 0;
}

int cmd_head(const Args& a) {
  if (!require(a, {"--log"})) return 2;
  std::string head, err;
  uint64_t count = 0;
  if (!ChainLog::verify(a.get("--log"), head, count, err)) {
    std::fprintf(stderr, "fimd: CHAIN BROKEN: %s\n", err.c_str());
    return 1;
  }
  std::printf("records=%llu head=%s\n", static_cast<unsigned long long>(count), head.c_str());
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2 || !std::strcmp(argv[1], "-h") || !std::strcmp(argv[1], "--help")) {
    std::fputs(kUsage, argc < 2 ? stderr : stdout);
    return argc < 2 ? 2 : 0;
  }
  std::string cmd = argv[1];
  Args a = parse_args(argc, argv, 2);
  if (!a.ok) return 2;

  if (cmd == "keygen") return cmd_keygen(a);
  if (cmd == "init") return cmd_init(a);
  if (cmd == "check") return cmd_check(a);
  if (cmd == "watch") return cmd_watch(a);
  if (cmd == "verify-log") return cmd_verify_log(a);
  if (cmd == "head") return cmd_head(a);

  std::fprintf(stderr, "fimd: unknown command '%s'\n\n%s", cmd.c_str(), kUsage);
  return 2;
}
