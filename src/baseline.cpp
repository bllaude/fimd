#include "baseline.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>

#include "crypto.hpp"
#include "util.hpp"

namespace fimd {

namespace fs = std::filesystem;

bool Scope::excluded(const std::string& path) const {
  for (const auto& e : excludes)
    if (under(path, e)) return true;
  return false;
}

static bool same_mtime_size(const struct stat& a, const struct stat& b) {
  return a.st_size == b.st_size && a.st_mtim.tv_sec == b.st_mtim.tv_sec &&
         a.st_mtim.tv_nsec == b.st_mtim.tv_nsec && a.st_ctim.tv_sec == b.st_ctim.tv_sec &&
         a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}

bool hash_path(const std::string& path, Entry& out) {
  struct stat lst;
  if (::lstat(path.c_str(), &lst) != 0) return false;

  if (S_ISLNK(lst.st_mode)) {
    char buf[4096];
    ssize_t n = ::readlink(path.c_str(), buf, sizeof buf);
    if (n < 0) return false;
    std::string target(buf, static_cast<size_t>(n));
    out.type = 'l';
    out.mode = lst.st_mode & 07777;
    out.uid = lst.st_uid;
    out.gid = lst.st_gid;
    out.size = static_cast<uint64_t>(n);
    out.sha256 = sha256_hex(target);
    return true;
  }
  if (!S_ISREG(lst.st_mode)) return false;

  // Up to four attempts: a writer racing the hash changes mtime/ctime/size
  // between the two fstat calls, in which case the digest may be torn.
  for (int attempt = 0; attempt < 4; ++attempt) {
    int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat before, after;
    if (::fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)) {
      ::close(fd);
      return false;  // swapped for a FIFO/device between lstat and open
    }
    std::string digest;
    bool ok = sha256_fd(fd, digest);
    bool stat_ok = ::fstat(fd, &after) == 0;
    ::close(fd);
    if (!ok || !stat_ok) return false;
    if (same_mtime_size(before, after) || attempt == 3) {
      out.type = 'f';
      out.mode = before.st_mode & 07777;
      out.uid = before.st_uid;
      out.gid = before.st_gid;
      out.size = static_cast<uint64_t>(after.st_size);
      out.sha256 = digest;
      return true;
    }
  }
  return false;
}

static void walk(const std::string& dir, const Scope& scope, Snapshot& out) {
  std::error_code ec;
  fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end;
  for (; !ec && it != end; it.increment(ec)) {
    std::string p = it->path().string();
    if (scope.excluded(p)) continue;
    struct stat st;
    if (::lstat(p.c_str(), &st) != 0) continue;
    if (S_ISDIR(st.st_mode)) {
      walk(p, scope, out);
    } else {
      Entry e;
      if (hash_path(p, e)) out[p] = e;
    }
  }
}

Snapshot scan(const Scope& scope) {
  Snapshot snap;
  for (const auto& r : scope.roots) {
    if (!scope.excluded(r)) walk(r, scope, snap);
  }
  return snap;
}

std::string serialize(const Baseline& b) {
  std::string s = "fimd-baseline v1\n";
  s += "created\t" + b.created + "\n";
  for (const auto& r : b.scope.roots) s += "root\t" + esc(r) + "\n";
  for (const auto& x : b.scope.excludes) s += "exclude\t" + esc(x) + "\n";
  char head[128];
  for (const auto& [path, e] : b.entries) {
    std::snprintf(head, sizeof head, "%c\t%o\t%u\t%u\t%llu\t", e.type, e.mode, e.uid, e.gid,
                  static_cast<unsigned long long>(e.size));
    s += head;
    s += e.sha256;
    s += '\t';
    s += esc(path);
    s += '\n';
  }
  return s;
}

bool parse(const std::string& text, Baseline& out, std::string& err) {
  out = Baseline{};
  auto lines = split(text, '\n');
  if (lines.empty() || lines[0] != "fimd-baseline v1") {
    err = "not a fimd baseline (bad header)";
    return false;
  }
  for (size_t i = 1; i < lines.size(); ++i) {
    const std::string& ln = lines[i];
    if (ln.empty()) continue;
    auto f = split(ln, '\t');
    if (f[0] == "created" && f.size() == 2) {
      out.created = f[1];
    } else if (f[0] == "root" && f.size() == 2) {
      out.scope.roots.push_back(unesc(f[1]));
    } else if (f[0] == "exclude" && f.size() == 2) {
      out.scope.excludes.push_back(unesc(f[1]));
    } else if ((f[0] == "f" || f[0] == "l") && f.size() == 7) {
      Entry e;
      e.type = f[0][0];
      char* endp = nullptr;
      e.mode = static_cast<uint32_t>(std::strtoul(f[1].c_str(), &endp, 8));
      if (*endp) { err = "line " + std::to_string(i + 1) + ": bad mode"; return false; }
      e.uid = static_cast<uint32_t>(std::strtoul(f[2].c_str(), &endp, 10));
      if (*endp) { err = "line " + std::to_string(i + 1) + ": bad uid"; return false; }
      e.gid = static_cast<uint32_t>(std::strtoul(f[3].c_str(), &endp, 10));
      if (*endp) { err = "line " + std::to_string(i + 1) + ": bad gid"; return false; }
      e.size = std::strtoull(f[4].c_str(), &endp, 10);
      if (*endp) { err = "line " + std::to_string(i + 1) + ": bad size"; return false; }
      if (f[5].size() != 64) { err = "line " + std::to_string(i + 1) + ": bad digest"; return false; }
      e.sha256 = f[5];
      out.entries[unesc(f[6])] = e;
    } else {
      err = "line " + std::to_string(i + 1) + ": unrecognised record";
      return false;
    }
  }
  if (out.scope.roots.empty()) {
    err = "baseline has no roots";
    return false;
  }
  return true;
}

bool save_signed(const Baseline& b, const std::string& path, const std::string& priv_key, std::string& err) {
  std::string text = serialize(b);
  Bytes sig;
  if (!sign_data(priv_key, text, sig, err)) return false;
  if (!write_file_atomic(path, text, 0644)) {
    err = "cannot write " + path + ": " + std::strerror(errno);
    return false;
  }
  std::string sigbytes(sig.begin(), sig.end());
  if (!write_file_atomic(path + ".sig", sigbytes, 0644)) {
    err = "cannot write " + path + ".sig: " + std::strerror(errno);
    return false;
  }
  return true;
}

bool load_verified(const std::string& path, const std::string& pub_key, Baseline& out, std::string& err) {
  std::string text, sigraw;
  if (!read_file(path, text)) { err = "cannot read " + path + ": " + std::strerror(errno); return false; }
  if (!read_file(path + ".sig", sigraw)) {
    err = "cannot read " + path + ".sig: " + std::strerror(errno);
    return false;
  }
  Bytes sig(sigraw.begin(), sigraw.end());
  if (!verify_data(pub_key, text, sig, err)) {
    err = "baseline signature verification failed (" + err + ")";
    return false;
  }
  if (!parse(text, out, err)) return false;
  out.file_sha256 = sha256_hex(text);
  return true;
}

}  // namespace fimd
