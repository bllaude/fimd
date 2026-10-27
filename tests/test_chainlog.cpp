// Unit tests for src/chainlog.cpp: hash-chained append-only log semantics.
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fstream>
#include <string>
#include <vector>

#include "chainlog.hpp"
#include "crypto.hpp"
#include "test_framework.hpp"
#include "util.hpp"

using namespace fimd;

namespace {

std::vector<std::string> lines_of(const std::string& text) {
  std::vector<std::string> out;
  size_t pos = 0;
  while (pos < text.size()) {
    size_t nl = text.find('\n', pos);
    if (nl == std::string::npos) nl = text.size();
    if (nl > pos) out.push_back(text.substr(pos, nl - pos));
    pos = nl + 1;
  }
  return out;
}

bool read_log(const std::string& path, std::string& text) { return read_file(path, text); }

}  // namespace

TEST(ChainLog, GenesisIs64Zeroes) {
  EXPECT_EQ(ChainLog::genesis(), std::string(64, '0'));
}

TEST(ChainLog, EmptyFileVerifiesWithGenesisHeadAndZeroCount) {
  tf::TempDir tmp("fimd_log_empty");
  ASSERT_TRUE(tmp.ok());
  const std::string p = tmp / "log";
  {
    std::ofstream os(p);
    os << "";
  }
  std::string head, err;
  uint64_t count = 999;
  ASSERT_TRUE(ChainLog::verify(p, head, count, err));
  EXPECT_EQ(head, ChainLog::genesis());
  EXPECT_EQ(count, static_cast<unsigned long>(0));

  // A nonexistent file also verifies as empty on open() (it gets created).
  ChainLog lg(tmp / "fresh");
  ASSERT_TRUE(lg.open(err));
  EXPECT_EQ(lg.head(), ChainLog::genesis());
  EXPECT_EQ(lg.count(), static_cast<unsigned long>(0));

  struct stat st;
  ASSERT_TRUE(::stat((tmp.path() + "/fresh").c_str(), &st) == 0);
  EXPECT_EQ(static_cast<int>(st.st_mode & 07777), 0600);  // created tight
}

TEST(ChainLog, AppendProducesWellFormedRecordsAndAdvancesHead) {
  tf::TempDir tmp("fimd_log_append");
  ASSERT_TRUE(tmp.ok());
  ChainLog lg(tmp / "log");
  std::string err;
  ASSERT_TRUE(lg.open(err));

  ASSERT_TRUE(lg.append("START", "/some/path", "", sha256_hex("baseline"), err));
  ASSERT_TRUE(lg.append("MODIFIED", "/etc/passwd", std::string(64, 'a'), std::string(64, 'b'), err));
  EXPECT_EQ(lg.count(), static_cast<unsigned long>(2));

  std::string text;
  ASSERT_TRUE(read_log(tmp / "log", text));
  auto recs = lines_of(text);
  ASSERT_TRUE(recs.size() == 2);
  auto f = split(recs[0], '\t');
  ASSERT_TRUE(f.size() == 8);
  EXPECT_EQ(f[0], "1");
  EXPECT_EQ(f[2], "START");
  EXPECT_EQ(f[3], "/some/path");
  EXPECT_EQ(f[6], ChainLog::genesis());   // first record chains from genesis
  auto g = split(recs[1], '\t');
  ASSERT_TRUE(g.size() == 8);
  EXPECT_EQ(g[0], "2");
  EXPECT_EQ(g[6], f[7]);                  // prev_hash of #2 == entry_hash of #1
  EXPECT_EQ(g[7], lg.head());             // head == last entry hash
  EXPECT_TRUE(f[7] != g[7]);              // distinct hashes
  EXPECT_EQ(g[2], "MODIFIED");
  EXPECT_EQ(g[4], std::string(64, 'a'));
  EXPECT_EQ(g[5], std::string(64, 'b'));

  std::string head;
  uint64_t count = 0;
  ASSERT_TRUE(ChainLog::verify(tmp / "log", head, count, err));
  EXPECT_EQ(head, lg.head());
  EXPECT_EQ(count, static_cast<unsigned long>(2));
}

TEST(ChainLog, EscapesPathControlBytesInRecordField) {
  tf::TempDir tmp("fimd_log_esc");
  ASSERT_TRUE(tmp.ok());
  ChainLog lg(tmp / "log");
  std::string err;
  ASSERT_TRUE(lg.open(err));
  ASSERT_TRUE(lg.append("ADDED", "/we" "\t" "ird\nname", "-", "-", err));

  std::string text;
  ASSERT_TRUE(read_log(tmp / "log", text));
  auto recs = lines_of(text);
  ASSERT_TRUE(recs.size() == 1);
  auto f = split(recs[0], '\t');
  ASSERT_TRUE(f.size() == 8);
  EXPECT_EQ(f[3], "/we%09ird%0Aname");     // single token, no raw tab/newline
  EXPECT_EQ(unesc(f[3]), "/we" "\t" "ird\nname");
}

TEST(ChainLog, ReopenContinuesSequenceFromPersistedHead) {
  tf::TempDir tmp("fimd_log_reopen");
  ASSERT_TRUE(tmp.ok());
  std::string err;
  {
    ChainLog a(tmp / "log");
    ASSERT_TRUE(a.open(err));
    ASSERT_TRUE(a.append("START", "-", "-", "-", err));
  }
  std::string head_after_1;
  {
    ChainLog b(tmp / "log");
    ASSERT_TRUE(b.open(err));
    EXPECT_EQ(b.count(), static_cast<unsigned long>(1));
    head_after_1 = b.head();
    ASSERT_TRUE(b.append("STOP", "-", "-", "-", err));
    EXPECT_EQ(b.count(), static_cast<unsigned long>(2));
  }
  std::string text;
  ASSERT_TRUE(read_log(tmp / "log", text));
  auto recs = lines_of(text);
  ASSERT_TRUE(recs.size() == 2);
  auto f2 = split(recs[1], '\t');
  ASSERT_TRUE(f2.size() == 8);
  EXPECT_EQ(f2[0], "2");
  EXPECT_EQ(f2[6], head_after_1);          // continued the chain written by process A
}

TEST(ChainLog, VerifyDetectsEditedRecordBody) {
  tf::TempDir tmp("fimd_log_edit");
  ASSERT_TRUE(tmp.ok());
  std::string err;
  {
    ChainLog lg(tmp / "log");
    ASSERT_TRUE(lg.open(err));
    for (int i = 0; i < 5; ++i) ASSERT_TRUE(lg.append("MODIFIED", "/f" + std::to_string(i), "a", "b", err));
  }
  std::string text;
  ASSERT_TRUE(read_log(tmp / "log", text));

  // Flip one character in the path field of record 3.
  auto recs = lines_of(text);
  ASSERT_TRUE(recs.size() == 5);
  auto f = split(recs[2], '\t');
  ASSERT_TRUE(f.size() == 8);
  f[3] += "x";
  std::string tampered;
  for (size_t i = 0; i < recs.size(); ++i) {
    if (i == 2) {
      std::string joined;
      for (size_t j = 0; j < f.size(); ++j) {
        if (j) joined += '\t';
        joined += f[j];
      }
      tampered += joined;
    } else {
      tampered += recs[i];
    }
    tampered += '\n';
  }
  ASSERT_TRUE(write_file_atomic(tmp / "log", tampered, 0600));

  std::string head;
  uint64_t count = 0;
  EXPECT_FALSE(ChainLog::verify(tmp / "log", head, count, err));
  EXPECT_TRUE(err.find("record 3") != std::string::npos);
  EXPECT_TRUE(err.find("entry hash mismatch") != std::string::npos);

  // The daemon must refuse to extend a broken chain.
  ChainLog lg(tmp / "log");
  EXPECT_FALSE(lg.open(err));
  EXPECT_TRUE(err.find("failed verification") != std::string::npos);
}

TEST(ChainLog, VerifyDetectsRemovedAndReorderedRecords) {
  tf::TempDir tmp("fimd_log_order");
  ASSERT_TRUE(tmp.ok());
  std::string err;
  std::string original;
  {
    ChainLog lg(tmp / "log");
    ASSERT_TRUE(lg.open(err));
    for (int i = 0; i < 4; ++i) ASSERT_TRUE(lg.append("ADDED", "/f" + std::to_string(i), "-", "-", err));
    ASSERT_TRUE(read_log(tmp / "log", original));
  }
  auto recs = lines_of(original);
  ASSERT_TRUE(recs.size() == 4);

  // Delete the middle record: sequence gap is caught even though the surviving
  // prefix still chains correctly.
  std::string removed = recs[0] + "\n" + recs[2] + "\n" + recs[3] + "\n";
  ASSERT_TRUE(write_file_atomic(tmp / "log", removed, 0600));
  std::string head;
  uint64_t count = 0;
  EXPECT_FALSE(ChainLog::verify(tmp / "log", head, count, err));
  EXPECT_TRUE(err.find("sequence number") != std::string::npos);

  // Swap records 2 and 3: prev_hash linkage breaks at the swapped pair.
  std::string swapped = recs[0] + "\n" + recs[2] + "\n" + recs[1] + "\n" + recs[3] + "\n";
  ASSERT_TRUE(write_file_atomic(tmp / "log", swapped, 0600));
  EXPECT_FALSE(ChainLog::verify(tmp / "log", head, count, err));
  EXPECT_TRUE(!err.empty());

  ASSERT_TRUE(write_file_atomic(tmp / "log", original, 0600));
  EXPECT_TRUE(ChainLog::verify(tmp / "log", head, count, err));
}

TEST(ChainLog, TruncatedTailStillSelfVerifiesButAnchorMismatchExposesIt) {
  tf::TempDir tmp("fimd_log_trunc");
  ASSERT_TRUE(tmp.ok());
  std::string err;
  std::string good_head;
  {
    ChainLog lg(tmp / "log");
    ASSERT_TRUE(lg.open(err));
    for (int i = 0; i < 6; ++i) ASSERT_TRUE(lg.append("MODIFIED", "/f", "-", "-", err));
    good_head = lg.head();
  }
  std::string text;
  ASSERT_TRUE(read_log(tmp / "log", text));
  auto recs = lines_of(text);
  ASSERT_TRUE(recs.size() == 6);

  // Drop the last record: the remaining chain is internally consistent...
  std::string truncated;
  for (size_t i = 0; i + 1 < recs.size(); ++i) truncated += recs[i] + "\n";
  ASSERT_TRUE(write_file_atomic(tmp / "log", truncated, 0600));
  std::string head;
  uint64_t count = 0;
  ASSERT_TRUE(ChainLog::verify(tmp / "log", head, count, err));
  EXPECT_EQ(count, static_cast<unsigned long>(5));
  EXPECT_TRUE(head != good_head);  // ...but an off-box --expect-head anchor catches it

  // And the daemon happily extends its own view of the shortened chain.
  ChainLog lg(tmp / "log");
  ASSERT_TRUE(lg.open(err));
  EXPECT_EQ(lg.count(), static_cast<unsigned long>(5));
}

TEST(ChainLog, VerifyRejectsPartialTrailingRecord) {
  tf::TempDir tmp("fimd_log_torn");
  ASSERT_TRUE(tmp.ok());
  std::string err;
  {
    ChainLog lg(tmp / "log");
    ASSERT_TRUE(lg.open(err));
    ASSERT_TRUE(lg.append("START", "-", "-", "-", err));
  }
  std::string text;
  ASSERT_TRUE(read_log(tmp / "log", text));
  ASSERT_TRUE(write_file_atomic(tmp / "log", text.substr(0, text.size() - 3), 0600));
  std::string head;
  uint64_t count = 0;
  EXPECT_FALSE(ChainLog::verify(tmp / "log", head, count, err));
  EXPECT_TRUE(err.find("partial record") != std::string::npos);
}

TEST(ChainLog, VerifyRejectsMalformedLines) {
  tf::TempDir tmp("fimd_log_malformed");
  ASSERT_TRUE(tmp.ok());
  std::string head;
  uint64_t count = 0;
  std::string err;

  ASSERT_TRUE(write_file_atomic(tmp / "short", "1\tts\tKIND\tpath\n", 0600));
  EXPECT_FALSE(ChainLog::verify(tmp / "short", head, count, err));
  EXPECT_TRUE(err.find("malformed") != std::string::npos);

  ASSERT_TRUE(write_file_atomic(tmp / "badseq", "7\tts\tKIND\tpath\ta\tb\t" + ChainLog::genesis() +
                                            "\tdeadbeef\n", 0600));
  EXPECT_FALSE(ChainLog::verify(tmp / "badseq", head, count, err));
  EXPECT_TRUE(err.find("sequence number") != std::string::npos);

  // Wrong prev_hash on record 1.
  ASSERT_TRUE(write_file_atomic(tmp / "badprev", "1\tts\tKIND\tpath\ta\tb\t" + std::string(64, 'f') +
                                            "\tdeadbeef\n", 0600));
  EXPECT_FALSE(ChainLog::verify(tmp / "badprev", head, count, err));
  EXPECT_TRUE(err.find("prev_hash") != std::string::npos);

  // Missing log file is an I/O error, not an empty log.
  EXPECT_FALSE(ChainLog::verify(tmp / "ghost", head, count, err));
  EXPECT_TRUE(err.find("cannot read") != std::string::npos);
}
TEST(ChainLog, ExclusiveFlockBlocksSecondOpener) {
  tf::TempDir tmp("fimd_log_flock");
  ASSERT_TRUE(tmp.ok());
  const std::string p = tmp / "log";
  std::string err;

  // A child process opens and closes the log first, so no lock is held when
  // the parent runs its contention checks below.
  pid_t kid = ::fork();
  ASSERT_TRUE(kid >= 0);
  if (kid == 0) {
    ChainLog c(p);
    bool ok = c.open(err);
    ::_exit(ok ? 0 : 11);  // closing the fd on exit releases the flock
  }
  int status = 0;
  ASSERT_TRUE(::waitpid(kid, &status, 0) == kid);
  ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  ChainLog a(p);
  ASSERT_TRUE(a.open(err));

  // An independent open file description (as another process or instance
  // would use) cannot also take the exclusive lock.
  int fd = ::open(p.c_str(), O_RDWR | O_CLOEXEC);
  ASSERT_TRUE(fd >= 0);
  EXPECT_TRUE(::flock(fd, LOCK_EX | LOCK_NB) != 0);  // EWOULDBLOCK: already held
  ::close(fd);

  // A second ChainLog instance reports the lock error.
  ChainLog b(p);
  EXPECT_FALSE(b.open(err));
  EXPECT_TRUE(err.find("locked") != std::string::npos);

  // Once the holder closes up, opening succeeds again.
  a.~ChainLog();
  ChainLog c(p);
  ASSERT_TRUE(c.open(err));
  EXPECT_EQ(c.count(), static_cast<unsigned long>(0));
}
