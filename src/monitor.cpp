#include "monitor.hpp"

#include <poll.h>
#include <signal.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <set>
#include <unordered_map>

#include "baseline.hpp"
#include "chainlog.hpp"
#include "util.hpp"

namespace fimd {

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

namespace {

volatile sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }

const char* kDash = "-";

// Fan-out for every detected change: stdout, optional syslog, optional chain log.
class Reporter {
 public:
  Reporter(ChainLog* log, bool use_syslog) : log_(log), syslog_(use_syslog) {
    if (syslog_) ::openlog("fimd", LOG_PID, LOG_AUTH);
  }
  ~Reporter() {
    if (syslog_) ::closelog();
  }

  void event(const std::string& kind, const std::string& path, const std::string& oldh,
             const std::string& newh) {
    ++events_;
    std::string ep = esc(path);
    std::printf("%s %s %s\n", utc_now().c_str(), kind.c_str(), ep.c_str());
    std::fflush(stdout);
    if (syslog_) ::syslog(LOG_WARNING, "%s %s old=%s new=%s", kind.c_str(), ep.c_str(), oldh.c_str(), newh.c_str());
    if (log_) {
      std::string err;
      if (!log_->append(kind, path, oldh, newh, err)) {
        std::fprintf(stderr, "fimd: LOG FAILURE: %s\n", err.c_str());
        if (syslog_) ::syslog(LOG_ERR, "log failure: %s", err.c_str());
      }
    }
  }

  void marker(const std::string& kind, const std::string& detail) { event(kind, kDash, kDash, detail); }
  uint64_t events() const { return events_; }

 private:
  ChainLog* log_;
  bool syslog_;
  uint64_t events_ = 0;
};

const std::string& hash_or_dash(const Entry* e, std::string& tmp) {
  if (!e) return tmp = kDash;
  return e->sha256;
}

// Compare two snapshots and report every difference. Returns the count.
uint64_t diff(const Snapshot& oldS, const Snapshot& newS, Reporter& rep) {
  uint64_t n = 0;
  std::string t1, t2;
  auto a = oldS.begin();
  auto b = newS.begin();
  while (a != oldS.end() || b != newS.end()) {
    if (b == newS.end() || (a != oldS.end() && a->first < b->first)) {
      rep.event("DELETED", a->first, hash_or_dash(&a->second, t1), kDash);
      ++a; ++n;
    } else if (a == oldS.end() || b->first < a->first) {
      rep.event("ADDED", b->first, kDash, hash_or_dash(&b->second, t2));
      ++b; ++n;
    } else {
      if (!a->second.same_content(b->second)) {
        rep.event("MODIFIED", a->first, a->second.sha256, b->second.sha256);
        ++n;
      } else if (!a->second.same_meta(b->second)) {
        rep.event("ATTRIB", a->first, a->second.sha256, b->second.sha256);
        ++n;
      }
      ++a; ++b;
    }
  }
  return n;
}

bool load_baseline(const std::string& baseline, const std::string& pub, Baseline& b) {
  std::string err;
  if (!load_verified(baseline, pub, b, err)) {
    std::fprintf(stderr, "fimd: %s\n", err.c_str());
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------

class Watcher {
 public:
  Watcher(const Scope& scope, Reporter& rep, Snapshot initial, int debounce_ms, int rescan_secs)
      : scope_(scope), rep_(rep), current_(std::move(initial)), debounce_(debounce_ms), rescan_secs_(rescan_secs) {}

  ~Watcher() {
    if (fd_ >= 0) ::close(fd_);
  }

  bool start() {
    fd_ = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd_ < 0) {
      std::fprintf(stderr, "fimd: inotify_init1: %s\n", std::strerror(errno));
      return false;
    }
    return true;
  }

  // Watches are armed before the scan that seeds `current_`, so nothing
  // between "scanned" and "watching" can be missed.
  void arm_all() {
    for (const auto& r : scope_.roots) add_tree(r, nullptr);
    if (failed_adds_)
      std::fprintf(stderr, "fimd: warning: %zu directories could not be watched (see earlier errors)\n", failed_adds_);
  }

  Snapshot& current() { return current_; }

  void run() {
    auto next_rescan = Clock::now() + std::chrono::seconds(rescan_secs_);
    Clock::time_point first_dirty;
    while (!g_stop) {
      int timeout = -1;
      if (!dirty_.empty()) {
        timeout = debounce_;
      } else if (rescan_secs_ > 0) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(next_rescan - Clock::now()).count();
        timeout = ms < 0 ? 0 : static_cast<int>(ms > 60000 ? 60000 : ms);
      }
      struct pollfd pfd = {fd_, POLLIN, 0};
      int r = ::poll(&pfd, 1, timeout);
      if (r < 0) {
        if (errno == EINTR) continue;
        std::fprintf(stderr, "fimd: poll: %s\n", std::strerror(errno));
        return;
      }
      if (r > 0) {
        bool had_dirty = !dirty_.empty();
        drain_events();
        if (!had_dirty && !dirty_.empty()) first_dirty = Clock::now();
      }
      auto now = Clock::now();
      bool quiet = (r == 0);
      if (!dirty_.empty() && (quiet || now - first_dirty > std::chrono::seconds(2))) process_dirty();
      if (need_rescan_ || (rescan_secs_ > 0 && now >= next_rescan)) {
        rescan(need_rescan_ ? "RESCAN_OVERFLOW" : "RESCAN_PERIODIC");
        need_rescan_ = false;
        next_rescan = Clock::now() + std::chrono::seconds(rescan_secs_);
      }
    }
  }

 private:
  static constexpr uint32_t kMask = IN_MODIFY | IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MOVED_FROM |
                                    IN_MOVED_TO | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR |
                                    IN_DONT_FOLLOW;

  // Recursively watch `dir`. When `files` is given, every non-directory path
  // seen under it is recorded so the caller can re-examine files that were
  // created before the watch existed.
  void add_tree(const std::string& dir, std::set<std::string>* files) {
    if (scope_.excluded(dir)) return;
    int wd = ::inotify_add_watch(fd_, dir.c_str(), kMask);
    if (wd < 0) {
      if (errno == ENOSPC && !warned_enospc_) {
        std::fprintf(stderr, "fimd: inotify watch limit reached; raise fs.inotify.max_user_watches\n");
        warned_enospc_ = true;
      } else if (errno != ENOENT && errno != ENOSPC) {
        std::fprintf(stderr, "fimd: cannot watch %s: %s\n", dir.c_str(), std::strerror(errno));
      }
      ++failed_adds_;
      return;
    }
    wd2dir_[wd] = dir;
    std::error_code ec;
    fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end;
    for (; !ec && it != end; it.increment(ec)) {
      std::string p = it->path().string();
      if (scope_.excluded(p)) continue;
      struct stat st;
      if (::lstat(p.c_str(), &st) != 0) continue;
      if (S_ISDIR(st.st_mode)) add_tree(p, files);
      else if (files) files->insert(p);
    }
  }

  void remove_subtree_watches(const std::string& prefix) {
    for (auto it = wd2dir_.begin(); it != wd2dir_.end();) {
      if (under(it->second, prefix)) {
        ::inotify_rm_watch(fd_, it->first);
        it = wd2dir_.erase(it);
      } else {
        ++it;
      }
    }
  }

  void mark_known_under(const std::string& prefix) {
    for (auto it = current_.lower_bound(prefix); it != current_.end() && under(it->first, prefix); ++it)
      dirty_.insert(it->first);
  }

  void drain_events() {
    alignas(struct inotify_event) char buf[65536];
    for (;;) {
      ssize_t n = ::read(fd_, buf, sizeof buf);
      if (n <= 0) break;  // EAGAIN: drained
      for (char* p = buf; p < buf + n;) {
        auto* ev = reinterpret_cast<struct inotify_event*>(p);
        p += sizeof(struct inotify_event) + ev->len;
        handle(*ev);
      }
    }
  }

  void handle(const struct inotify_event& ev) {
    if (ev.mask & IN_Q_OVERFLOW) {
      need_rescan_ = true;
      return;
    }
    if (ev.mask & IN_IGNORED) {
      wd2dir_.erase(ev.wd);
      return;
    }
    auto it = wd2dir_.find(ev.wd);
    if (it == wd2dir_.end()) return;
    std::string dir = it->second;
    std::string path = ev.len ? (dir == "/" ? "/" + std::string(ev.name) : dir + "/" + ev.name) : dir;

    if (ev.mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
      // The watched directory itself went away or was renamed; its stored
      // path is no longer valid. Treat the whole subtree as changed.
      remove_subtree_watches(dir);
      mark_known_under(dir);
      return;
    }
    if (scope_.excluded(path)) return;

    if (ev.mask & IN_ISDIR) {
      if (ev.mask & (IN_DELETE | IN_MOVED_FROM)) {
        remove_subtree_watches(path);
        mark_known_under(path);
      } else if (ev.mask & (IN_CREATE | IN_MOVED_TO)) {
        std::set<std::string> found;
        add_tree(path, &found);
        dirty_.insert(found.begin(), found.end());
      }
      return;
    }
    dirty_.insert(path);
  }

  void process_dirty() {
    std::set<std::string> batch;
    batch.swap(dirty_);
    std::string t;
    for (const auto& path : batch) {
      Entry now;
      bool exists = hash_path(path, now);
      auto it = current_.find(path);
      if (exists) {
        if (it == current_.end()) {
          rep_.event("ADDED", path, kDash, now.sha256);
        } else if (!it->second.same_content(now)) {
          rep_.event("MODIFIED", path, it->second.sha256, now.sha256);
        } else if (!it->second.same_meta(now)) {
          rep_.event("ATTRIB", path, it->second.sha256, now.sha256);
        }
        current_[path] = now;
      } else if (it != current_.end()) {
        rep_.event("DELETED", path, hash_or_dash(&it->second, t), kDash);
        current_.erase(it);
      }
    }
  }

  void rescan(const char* why) {
    rep_.marker(why, kDash);
    arm_all();  // pick up directories created while the queue overflowed
    Snapshot fresh = scan(scope_);
    diff(current_, fresh, rep_);
    current_ = std::move(fresh);
  }

  Scope scope_;
  Reporter& rep_;
  Snapshot current_;
  int debounce_;
  int rescan_secs_;
  int fd_ = -1;
  std::unordered_map<int, std::string> wd2dir_;
  std::set<std::string> dirty_;
  bool need_rescan_ = false;
  bool warned_enospc_ = false;
  size_t failed_adds_ = 0;
};

}  // namespace

int run_check(const CheckOptions& opt) {
  Baseline base;
  if (!load_baseline(opt.baseline, opt.pub_key, base)) return 2;

  std::unique_ptr<ChainLog> log;
  if (!opt.log.empty()) {
    log = std::make_unique<ChainLog>(opt.log);
    std::string err;
    if (!log->open(err)) {
      std::fprintf(stderr, "fimd: %s\n", err.c_str());
      return 2;
    }
  }
  Reporter rep(log.get(), opt.use_syslog);
  rep.marker("CHECK_START", base.file_sha256);
  Snapshot live = scan(base.scope);
  uint64_t n = diff(base.entries, live, rep);
  rep.marker("CHECK_END", std::to_string(n) + "_differences");
  std::fprintf(stderr, "fimd: %zu files in baseline, %zu on disk, %llu differences\n", base.entries.size(),
               live.size(), static_cast<unsigned long long>(n));
  return n ? 1 : 0;
}

int run_watch(const WatchOptions& opt) {
  Baseline base;
  if (!load_baseline(opt.baseline, opt.pub_key, base)) return 2;

  std::unique_ptr<ChainLog> log;
  if (!opt.log.empty()) {
    log = std::make_unique<ChainLog>(opt.log);
    std::string err;
    if (!log->open(err)) {
      std::fprintf(stderr, "fimd: %s\n", err.c_str());
      return 2;
    }
  }
  Reporter rep(log.get(), opt.use_syslog);

  struct sigaction sa;
  std::memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_signal;  // no SA_RESTART: poll() must return EINTR
  ::sigaction(SIGINT, &sa, nullptr);
  ::sigaction(SIGTERM, &sa, nullptr);

  rep.marker("START", base.file_sha256);

  Watcher w(base.scope, rep, base.entries, opt.debounce_ms, opt.rescan_secs);
  if (!w.start()) return 2;
  w.arm_all();

  // Anything that changed while the daemon was not running shows up here.
  Snapshot live = scan(base.scope);
  uint64_t offline = diff(base.entries, live, rep);
  w.current() = std::move(live);
  std::fprintf(stderr, "fimd: watching %zu roots, %zu files; %llu changes since baseline\n",
               base.scope.roots.size(), w.current().size(), static_cast<unsigned long long>(offline));

  w.run();

  rep.marker("STOP", kDash);
  return 0;
}

}  // namespace fimd
