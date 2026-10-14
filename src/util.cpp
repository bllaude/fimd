#include "util.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>

namespace fimd {

std::string esc(const std::string& s) {
  static const char* hexd = "0123456789ABCDEF";
  std::string out;
  out.reserve(s.size());
  for (unsigned char c : s) {
    if (c == '%' || c < 0x20 || c == 0x7f) {
      out += '%';
      out += hexd[c >> 4];
      out += hexd[c & 0xf];
    } else {
      out += static_cast<char>(c);
    }
  }
  return out;
}

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

std::string unesc(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '%' && i + 2 < s.size() && hexval(s[i + 1]) >= 0 && hexval(s[i + 2]) >= 0) {
      out += static_cast<char>(hexval(s[i + 1]) * 16 + hexval(s[i + 2]));
      i += 2;
    } else {
      out += s[i];
    }
  }
  return out;
}

bool read_file(const std::string& path, std::string& out) {
  int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  out.clear();
  char buf[65536];
  for (;;) {
    ssize_t n = ::read(fd, buf, sizeof buf);
    if (n < 0) {
      if (errno == EINTR) continue;
      ::close(fd);
      return false;
    }
    if (n == 0) break;
    out.append(buf, static_cast<size_t>(n));
  }
  ::close(fd);
  return true;
}

bool write_file_atomic(const std::string& path, const std::string& data, mode_t mode) {
  std::string tmp = path + ".tmp." + std::to_string(::getpid());
  int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
  if (fd < 0) return false;
  size_t off = 0;
  while (off < data.size()) {
    ssize_t n = ::write(fd, data.data() + off, data.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      ::close(fd);
      ::unlink(tmp.c_str());
      return false;
    }
    off += static_cast<size_t>(n);
  }
  if (::fsync(fd) != 0) {
    ::close(fd);
    ::unlink(tmp.c_str());
    return false;
  }
  ::close(fd);
  if (::rename(tmp.c_str(), path.c_str()) != 0) {
    ::unlink(tmp.c_str());
    return false;
  }
  return true;
}

std::vector<std::string> split(const std::string& s, char sep) {
  std::vector<std::string> parts;
  size_t start = 0;
  for (;;) {
    size_t pos = s.find(sep, start);
    if (pos == std::string::npos) {
      parts.push_back(s.substr(start));
      break;
    }
    parts.push_back(s.substr(start, pos - start));
    start = pos + 1;
  }
  return parts;
}

std::string utc_now() {
  struct timespec ts;
  ::clock_gettime(CLOCK_REALTIME, &ts);
  struct tm tm;
  ::gmtime_r(&ts.tv_sec, &tm);
  char buf[40];
  size_t n = std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%S", &tm);
  std::snprintf(buf + n, sizeof buf - n, ".%03ldZ", ts.tv_nsec / 1000000);
  return buf;
}

bool under(const std::string& p, const std::string& prefix) {
  if (p == prefix) return true;
  if (prefix == "/") return !p.empty() && p[0] == '/';
  return p.size() > prefix.size() && p.compare(0, prefix.size(), prefix) == 0 && p[prefix.size()] == '/';
}

std::string normalize_path(const std::string& p) {
  namespace fs = std::filesystem;
  std::string s = fs::absolute(fs::path(p)).lexically_normal().string();
  while (s.size() > 1 && s.back() == '/') s.pop_back();
  return s;
}

}  // namespace fimd
