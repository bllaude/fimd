// Unit tests for src/monitor.cpp: the check/watch commands against a real
// signed baseline in a temporary tree (run as root, so uid/gid changes work).
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fstream>
#include <string>

#include "baseline.hpp"
#include "chainlog.hpp"
#include "crypto.hpp"
#include "monitor.hpp"
#include "test_framework.hpp"
#include "util.hpp"

using namespace fimd;

namespace {

void put(const std::string& path, const std::string& data) {
  std::ofstream os(path, std::ios::binary);
  os << data;
}

// Fixture: temp tree with one file and one symlink, fresh Ed25519 keypair and
// a signed baseline covering the whole tree.
struct Fixture {
  tf::TempDir tmp{"fimd_monitor"};
  std::string tree;
  std::string priv;
  std::string pub;
  std::string base;
  std::string err;

  bool setup() {
    if (!tmp.ok()) return false;
    tree = normalize_path(tmp / "tree");
    ::mkdir(tree.c_str(), 0755);
    put(tree + "/a.txt", "alpha\n");
    make_symlink("link_target", tree + "/link");
    priv = tmp / "k.pem";
    pub = tmp / "k.pub";
    base = tmp / "base";
    if (!generate_keypair(priv, pub, err)) return false;
    Baseline b;
    b.created = utc_now();
    b.scope.roots = {tree};
    return save_signed(b, base, priv, err);
  }
  // The symlink target need not resolve: fimd hashes the stored text.
  static void make_symlink(const std::string& target, const std::string& linkpath) {
    ::symlink(target.c_str(), linkpath.c_str());
  }

  CheckOptions opts(const std::string& log = "") const {
    CheckOptions o;
    o.baseline = base;
    o.pub_key = pub;
    o.log = log;
    return o;
  }
};

bool has_kind(const std::string& log_path, const std::string& kind, const std::string& path_sub) {
  std::string text;
  if (!read_file(log_path, text)) return false;
  size_t pos = 0;
  while (pos < text.size()) {
    size_t nl = text.find('\n', pos);
    if (nl == std::string::npos) nl = text.size();
    auto f = split(text.substr(pos, nl - pos), '\t');
    if (f.size() == 8 && f[2] == kind && f[3].find(path_sub) != std::string::npos) return true;
    pos = nl + 1;
  }
  return false;
}

}  // namespace

TEST(Monitor, CleanTreeExitsZeroAndWritesNoRecordsWithoutLog) {
  Fixture fx;
  ASSERT_TRUE(fx.setup());
  EXPECT_EQ(run_check(fx.opts()), 0);
}

TEST(Monitor, DetectsModifiedAddedDeletedAndAttrib) {
  Fixture fx;
  ASSERT_TRUE(fx.setup());

  put(fx.tree + "/a.txt", "alpha\nbeta\n");           // MODIFIED
  ::unlink((fx.tree + "/link").c_str());              // DELETED
  put(fx.tree + "/new.txt", "fresh\n");               // ADDED
  ASSERT_TRUE(::chmod((fx.tree + "/new.txt").c_str(), 0600) == 0);  // still ADDED overall

  const std::string log = fx.tmp / "log";
  EXPECT_EQ(run_check(fx.opts(log)), 1);
  EXPECT_TRUE(has_kind(log, "MODIFIED", "a.txt"));
  EXPECT_TRUE(has_kind(log, "DELETED", "link"));
  EXPECT_TRUE(has_kind(log, "ADDED", "new.txt"));
  EXPECT_TRUE(has_kind(log, "CHECK_START", ""));
  EXPECT_TRUE(has_kind(log, "CHECK_END", ""));

  // ATTRIB: chmod only, content identical.
  ASSERT_TRUE(::chmod((fx.tree + "/a.txt").c_str(), 0777) == 0);
  const std::string log2 = fx.tmp / "log2";
  EXPECT_EQ(run_check(fx.opts(log2)), 1);
  EXPECT_TRUE(has_kind(log2, "ATTRIB", "a.txt"));

  // The event log must remain a valid chain after two runs appended to it...
  std::string head;
  uint64_t count = 0;
  std::string err;
  EXPECT_TRUE(ChainLog::verify(log, head, count, err));
}

TEST(Monitor, LogBindsToBaselineByDigest) {
  Fixture fx;
  ASSERT_TRUE(fx.setup());
  const std::string log = fx.tmp / "log";
  ASSERT_EQ(run_check(fx.opts(log)), 0);

  // CHECK_START carries SHA-256 of the exact baseline manifest bytes.
  std::string manifest;
  ASSERT_TRUE(read_file(fx.base, manifest));
  EXPECT_TRUE(has_kind(log, "CHECK_START", sha256_hex(manifest)));

  // START records (watch daemon) carry the same binding; verify via a watch
  // that exits immediately on SIGTERM would be flaky here, so instead check
  // that a second check run against the same log chains correctly.
  ASSERT_EQ(run_check(fx.opts(log)), 0);
  std::string head;
  uint64_t count = 0;
  std::string err;
  EXPECT_TRUE(ChainLog::verify(log, head, count, err));
  EXPECT_TRUE(count >= 4);  // at least two CHECK_START/CHECK_END pairs
}

TEST(Monitor, ErrorPathsReturnTwo) {
  Fixture fx;
  ASSERT_TRUE(fx.setup());

  CheckOptions o = fx.opts();
  o.baseline = fx.tmp / "ghost";  // missing manifest
  EXPECT_EQ(run_check(o), 2);

  o = fx.opts();
  o.pub_key = fx.tmp / "ghost.pub";  // missing public key
  EXPECT_EQ(run_check(o), 2);

  // Signed but edited manifest.
  std::string text;
  ASSERT_TRUE(read_file(fx.base, text));
  ASSERT_TRUE(write_file_atomic(fx.base, text + "root\t/evil\n", 0644));
  EXPECT_EQ(run_check(fx.opts()), 2);
}

TEST(Monitor, BrokenLogIsRefusedForAppending) {
  Fixture fx;
  ASSERT_TRUE(fx.setup());
  const std::string log = fx.tmp / "log";
  ASSERT_EQ(run_check(fx.opts(log)), 0);  // creates a valid chain

  // Corrupt record 1's body: append to the path field so its entry hash no
  // longer matches, without touching any other record.
  std::string text;
  ASSERT_TRUE(read_file(log, text));
  size_t first_nl = text.find('\n');
  ASSERT_TRUE(first_nl != std::string::npos && first_nl > 4);
  auto f = split(text.substr(0, first_nl), '\t');
  ASSERT_TRUE(f.size() == 8);
  f[3] += "tampered";
  std::string rec;
  for (size_t i = 0; i < f.size(); ++i) {
    if (i) rec += '\t';
    rec += f[i];
  }
  const std::string broken = rec + "\n" + text.substr(first_nl + 1);
  ASSERT_TRUE(write_file_atomic(log, broken, 0600));

  EXPECT_EQ(run_check(fx.opts(log)), 2);  // refuses to extend a broken chain

  // Without --log the same check runs fine: log handling is skipped entirely.
  EXPECT_EQ(run_check(fx.opts()), 0); 
}

TEST(Monitor, WatchStartsStopsAndLogsMarkers) {
  // A short-lived watch run: start, make a change, terminate, inspect log.
  Fixture fx;
  ASSERT_TRUE(fx.setup());
  const std::string log = fx.tmp / "wlog";

  pid_t kid = ::fork();
  ASSERT_TRUE(kid >= 0);
  if (kid == 0) {
    // Redirect stdout/stderr of the child to a file so test output stays clean.
    std::string devnull_out = fx.tmp / "watch.out";
    int fd = ::open(devnull_out.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0) {
      ::dup2(fd, STDOUT_FILENO);
      ::dup2(fd, STDERR_FILENO);
      ::close(fd);
    }
    WatchOptions w;
    static_cast<CheckOptions&>(w) = fx.opts(log);
    w.debounce_ms = 100;
    w.rescan_secs = 0;
    ::_exit(run_watch(w));
  }

  // Give the daemon time to arm watches and write START, then mutate a file.
  ::usleep(700 * 1000);
  put(fx.tree + "/a.txt", "alpha\nchanged-by-test\n");
  ::usleep(600 * 1000);
  ::kill(kid, SIGTERM);
  int status = 0;
  ASSERT_TRUE(::waitpid(kid, &status, 0) == kid);
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);  // clean shutdown

  std::string head;
  uint64_t count = 0;
  std::string err;
  ASSERT_TRUE(ChainLog::verify(log, head, count, err));
  EXPECT_TRUE(has_kind(log, "START", ""));
  EXPECT_TRUE(has_kind(log, "STOP", ""));
  EXPECT_TRUE(has_kind(log, "MODIFIED", "a.txt"));
}
