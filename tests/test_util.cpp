// Unit tests for src/util.cpp: escaping, splitting, path helpers and I/O.
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <string>

#include "test_framework.hpp"
#include "util.hpp"

using namespace fimd;

namespace {

bool exists(const std::string& p) {
  struct stat st;
  return ::lstat(p.c_str(), &st) == 0;
}

}  // namespace

TEST(Util, EscLeavesPrintableAsciiUntouched) {
  const std::string s = "/some/dir/file-Name.txt~!@#$^&*()_+={}[]|:;<>,.?";
  EXPECT_EQ(esc(s), s);
  EXPECT_EQ(esc(""), std::string());
}

TEST(Util, EscPercentControlAndDel) {
  EXPECT_EQ(esc("%"), "%25");
  EXPECT_EQ(esc("\t"), "%09");
  EXPECT_EQ(esc("\n"), "%0A");
  EXPECT_EQ(esc("\r"), "%0D");
  EXPECT_EQ(esc(std::string(1, '\0')), "%00");
  EXPECT_EQ(esc(std::string(1, '\x7f')), "%7F");
  EXPECT_EQ(esc("we\ti\nrd%"), "we%09i%0Ard%25");
}

TEST(Util, UnescIsExactInverseOfEsc) {
  std::string orig;
  for (int c = 0; c < 256; ++c) orig += static_cast<char>(c);
  EXPECT_EQ(unesc(esc(orig)), orig);

  const char* samples[] = {"plain/path.txt", "we\tird", "a%b", "\x01\x02\xff hi", ""};
  for (const char* s : samples) {
    std::string o = s;
    EXPECT_EQ(unesc(esc(o)), o);
  }
}

TEST(Util, UnescPassesThroughLoneOrInvalidPercents) {
  EXPECT_EQ(unesc("%zz"), "%zz");
  EXPECT_EQ(unesc("%2"), "%2");   // truncated escape at end of string
  EXPECT_EQ(unesc("50%"), "50%");
  EXPECT_EQ(unesc("%41"), "A");   // valid lowercase-free escape decodes
  EXPECT_EQ(unesc("%61"), "a");
}

TEST(Util, SplitBasics) {
  auto parts = split("a:b:c", ':');
  ASSERT_TRUE(parts.size() == 3);
  EXPECT_EQ(parts[0], "a");
  EXPECT_EQ(parts[1], "b");
  EXPECT_EQ(parts[2], "c");

  auto empties = split(":a:", ':');
  ASSERT_TRUE(empties.size() == 3);
  EXPECT_EQ(empties[0], "");
  EXPECT_EQ(empties[1], "a");
  EXPECT_EQ(empties[2], "");

  auto one = split("solo", ':');
  ASSERT_TRUE(one.size() == 1);
  EXPECT_EQ(one[0], "solo");

  auto empty = split("", ':');
  ASSERT_TRUE(empty.size() == 1);
  EXPECT_EQ(empty[0], "");

  auto tabs = split("a\tb\tc\td\te\tf\tg", '\t');
  EXPECT_TRUE(tabs.size() == 7);
}

TEST(Util, UnderComponentwisePrefixMatching) {
  EXPECT_TRUE(under("/etc", "/etc"));
  EXPECT_TRUE(under("/etc/hosts", "/etc"));
  EXPECT_TRUE(under("/etc/apache2/sites-enabled/x", "/etc"));
  EXPECT_FALSE(under("/etcetera/passwd", "/etc"));  // textual but not component-wise
  EXPECT_FALSE(under("/et", "/etc"));
  EXPECT_FALSE(under("/", "/etc"));
  EXPECT_TRUE(under("/anything", "/"));
  EXPECT_FALSE(under("", "/"));
  EXPECT_TRUE(under("/", "/"));
}

TEST(Util, NormalizePathAbsolutisesAndCollapses) {
  tf::TempDir tmp("fimd_util_norm");
  ASSERT_TRUE(tmp.ok());
  const std::string expect_base = tmp.path();  // mkdtemp returns an absolute path

  EXPECT_EQ(normalize_path(tmp / "a/b"), expect_base + "/a/b");
  EXPECT_EQ(normalize_path((tmp / "a") + "/./b"), expect_base + "/a/b");
  EXPECT_EQ(normalize_path((tmp / "a") + "/b/../c"), expect_base + "/a/c");
  EXPECT_EQ(normalize_path((tmp / "a/") + ""), expect_base + "/a");  // trailing slash removed
  EXPECT_EQ(normalize_path((tmp / "a") + "//b"), expect_base + "/a/b");
  EXPECT_EQ(normalize_path("/"), "/");
  EXPECT_EQ(normalize_path("/a/../.."), "/");  // cannot escape the root
}

TEST(Util, ReadFileRoundtripAndErrors) {
  tf::TempDir tmp("fimd_util_io");
  ASSERT_TRUE(tmp.ok());
  const std::string p = tmp / "payload";
  const std::string want = "line1\nline2\n\ttabbed\xffbinary\x00nul\n";
  {
    std::ofstream os(p, std::ios::binary);
    os << want;
  }
  std::string got;
  ASSERT_TRUE(read_file(p, got));
  EXPECT_EQ(got, want);

  EXPECT_FALSE(read_file(static_cast<std::string>(tmp / "does_not_exist"), got));

  struct stat st;
  ASSERT_TRUE(::stat(tmp.path().c_str(), &st) == 0);
  EXPECT_TRUE(S_ISDIR(st.st_mode));  // sanity on the temp dir itself
}

TEST(Util, WriteFileAtomicCreatesWithModeAndOverwrites) {
  tf::TempDir tmp("fimd_util_atomic");
  ASSERT_TRUE(tmp.ok());
  const std::string p = tmp / "out";
  ASSERT_TRUE(write_file_atomic(p, "hello", 0600));
  std::string got;
  ASSERT_TRUE(read_file(p, got));
  EXPECT_EQ(got, "hello");

  struct stat st;
  ASSERT_TRUE(::stat(p.c_str(), &st) == 0);
  EXPECT_EQ(static_cast<int>(st.st_mode & 07777), 0600);

  // Overwriting an existing file works (rename is allowed over it).
  ASSERT_TRUE(write_file_atomic(p, "second", 0644));
  ASSERT_TRUE(read_file(p, got));
  EXPECT_EQ(got, "second");

  // No stray temporary files are left behind.
  EXPECT_FALSE(exists(p + ".tmp." + std::to_string(::getpid())));

  // Failure path: parent directory does not exist.
  EXPECT_FALSE(write_file_atomic(static_cast<std::string>(tmp / "missing") + "/file", "x", 0644));
}

TEST(Util, UtcNowLooksLikeRfc3339WithMillis) {
  const std::string ts = utc_now();
  ASSERT_TRUE(ts.size() == 24);
  EXPECT_TRUE(ts[4] == '-' && ts[7] == '-' && ts[10] == 'T');
  EXPECT_TRUE(ts[13] == ':' && ts[16] == ':' && ts[19] == '.');
  EXPECT_TRUE(ts.back() == 'Z');
  for (size_t i = 0; i < ts.size(); ++i) {
    if (i == 4 || i == 7 || i == 10 || i == 13 || i == 16 || i == 19) continue;
    EXPECT_TRUE(ts[i] >= '0' && ts[i] <= '9');
  }
}

TEST(Util, EscUnescSurviveNastyPathsOnDisk) {
  // End-to-end flavour: a path with tab and percent survives esc/unesc so it
  // can live as a single token in the manifest or log line format.
  const std::string nasty = "/dir with space/we" "\t" "ird%name\nnewline";
  const std::string e = esc(nasty);
  EXPECT_TRUE(e.find('\t') == std::string::npos);
  EXPECT_TRUE(e.find('\n') == std::string::npos);
  EXPECT_TRUE(e.find(' ') != std::string::npos);  // spaces are legal tokens
  EXPECT_EQ(unesc(e), nasty);
}
