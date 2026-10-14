#include "chainlog.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "crypto.hpp"
#include "util.hpp"

namespace fimd {

std::string ChainLog::genesis() { return std::string(64, '0'); }

static std::string entry_hash(uint64_t seq, const std::string& ts, const std::string& kind,
                              const std::string& epath, const std::string& oldh, const std::string& newh,
                              const std::string& prev) {
  std::string in = "fimd-log-v1\n";
  in += std::to_string(seq) + "\n" + ts + "\n" + kind + "\n" + epath + "\n" + oldh + "\n" + newh + "\n" + prev;
  return sha256_hex(in);
}

ChainLog::~ChainLog() {
  if (fd_ >= 0) ::close(fd_);
}

bool ChainLog::verify(const std::string& path, std::string& head, uint64_t& count, std::string& err) {
  std::string text;
  if (!read_file(path, text)) {
    err = "cannot read " + path + ": " + std::strerror(errno);
    return false;
  }
  head = genesis();
  count = 0;
  if (text.empty()) return true;
  if (text.back() != '\n') {
    err = "log ends in a partial record (torn write or truncation)";
    return false;
  }
  size_t pos = 0;
  while (pos < text.size()) {
    size_t nl = text.find('\n', pos);
    std::string line = text.substr(pos, nl - pos);
    pos = nl + 1;
    auto f = split(line, '\t');
    uint64_t want = count + 1;
    if (f.size() != 8) {
      err = "record " + std::to_string(want) + ": malformed";
      return false;
    }
    if (f[0] != std::to_string(want)) {
      err = "record " + std::to_string(want) + ": sequence number is " + f[0] + " (record removed or reordered)";
      return false;
    }
    if (f[6] != head) {
      err = "record " + std::to_string(want) + ": prev_hash does not match preceding record";
      return false;
    }
    std::string h = entry_hash(want, f[1], f[2], f[3], f[4], f[5], f[6]);
    if (h != f[7]) {
      err = "record " + std::to_string(want) + ": entry hash mismatch (record was modified)";
      return false;
    }
    head = h;
    count = want;
  }
  return true;
}

bool ChainLog::open(std::string& err) {
  fd_ = ::open(path_.c_str(), O_RDWR | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd_ < 0) {
    err = "cannot open log " + path_ + ": " + std::strerror(errno);
    return false;
  }
  if (::flock(fd_, LOCK_EX | LOCK_NB) != 0) {
    err = "log " + path_ + " is locked by another process";
    return false;
  }
  if (!verify(path_, head_, seq_, err)) {
    err = "existing log failed verification: " + err;
    return false;
  }
  return true;
}

bool ChainLog::append(const std::string& kind, const std::string& path, const std::string& old_hash,
                      const std::string& new_hash, std::string& err) {
  uint64_t seq = seq_ + 1;
  std::string ts = utc_now();
  std::string ep = esc(path);
  std::string h = entry_hash(seq, ts, kind, ep, old_hash, new_hash, head_);
  std::string line = std::to_string(seq) + "\t" + ts + "\t" + kind + "\t" + ep + "\t" + old_hash + "\t" +
                     new_hash + "\t" + head_ + "\t" + h + "\n";
  size_t off = 0;
  while (off < line.size()) {
    ssize_t n = ::write(fd_, line.data() + off, line.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      err = std::string("log write failed: ") + std::strerror(errno);
      return false;
    }
    off += static_cast<size_t>(n);
  }
  if (::fdatasync(fd_) != 0) {
    err = std::string("log fsync failed: ") + std::strerror(errno);
    return false;
  }
  seq_ = seq;
  head_ = h;
  return true;
}

}  // namespace fimd
