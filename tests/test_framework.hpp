// Minimal C++17 unit-test framework: TEST() cases, EXPECT/ASSERT checks and a
// RAII TempDir helper. main() lives in test_main.cpp.
#pragma once

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace tf {

struct TestCase {
  const char* suite;
  const char* name;
  std::function<void(bool&)> fn;
};

inline std::vector<TestCase>& registry() {
  static std::vector<TestCase> r;
  return r;
}

inline int& failures_here() {
  static int n = 0;
  return n;
}

struct Registrar {
  Registrar(const char* suite, const char* name, std::function<void(bool&)> fn) {
    registry().push_back({suite, name, std::move(fn)});
  }
};

inline void report_failure(const char* file, int line, const std::string& expr) {
  ++failures_here();
  std::fprintf(stderr, "    FAIL %s:%d: %s\n", file, line, expr.c_str());
}

template <typename A, typename B>
void expect_eq(const A& a, const B& b, const char* file, int line, const char* sa, const char* sb) {
  if (!(a == b)) {
    std::ostringstream os;
    os << sa << " == " << sb << "\n      left : " << a << "\n      right: " << b;
    report_failure(file, line, os.str());
  }
}

inline void expect_true(bool v, const char* file, int line, const char* s) {
  if (!v) report_failure(file, line, std::string("expected true: ") + s);
}

inline void expect_false(bool v, const char* file, int line, const char* s) {
  if (v) report_failure(file, line, std::string("expected false: ") + s);
}

// RAII temporary directory removed on destruction (best effort, recursive).
class TempDir {
 public:
  explicit TempDir(const std::string& prefix = "fimd_test") {
    std::string tmpl = "/tmp/" + prefix + "_XXXXXX";
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    const char* p = mkdtemp(buf.data());
    if (p == nullptr) {
      ok_ = false;
      return;
    }
    path_ = p;
    ok_ = true;
  }
  ~TempDir() {
    if (ok_) remove_recursive(path_.c_str());
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;

  bool ok() const { return ok_; }
  const std::string& path() const { return path_; }
  std::string operator/(const std::string& rel) const { return path_ + "/" + rel; }

 private:
  static void remove_recursive(const char* path) {
    struct stat st;
    if (lstat(path, &st) != 0) return;
    if (S_ISDIR(st.st_mode)) {
      // opendir may fail if already removed by another cleanup; ignore.
      if (DIR* d = opendir(path)) {
        while (struct dirent* de = readdir(d)) {
          std::string name = de->d_name;
          if (name != "." && name != "..") {
            std::string child = std::string(path) + "/" + name;
            remove_recursive(child.c_str());
          }
        }
        closedir(d);
      }
      rmdir(path);
    } else {
      unlink(path);
    }
  }

  std::string path_;
  bool ok_ = false;
};

int run_all(const std::string& filter);

}  // namespace tf

#define TF_CAT2(a, b) a##b
#define TF_CAT(a, b) TF_CAT2(a, b)

#define TEST(suite, name)                                                            \
  static void TF_CAT(suite, TF_CAT(_, name))([[maybe_unused]] bool& _tf_fatal);                      \
  static ::tf::Registrar TF_CAT(tf_reg_, __LINE__)(#suite, #name,                    \
                                                   &TF_CAT(suite, TF_CAT(_, name))); \
  static void TF_CAT(suite, TF_CAT(_, name))([[maybe_unused]] bool& _tf_fatal)

#define EXPECT_TRUE(x) ::tf::expect_true((x), __FILE__, __LINE__, #x)
#define EXPECT_FALSE(x) ::tf::expect_false((x), __FILE__, __LINE__, #x)
#define EXPECT_EQ(a, b) ::tf::expect_eq((a), (b), __FILE__, __LINE__, #a, #b)
#define ASSERT_TRUE(x)                                       \
  do {                                                       \
    if (!(x)) {                                              \
      ::tf::report_failure(__FILE__, __LINE__, "ASSERT: " #x); \
      _tf_fatal = true;                                      \
      return;                                                \
    }                                                        \
  } while (0)
