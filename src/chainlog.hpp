#pragma once
#include <cstdint>
#include <string>
#include <utility>

namespace fimd {

// Append-only, hash-chained event log. One record per line:
//
//   seq \t timestamp \t kind \t path \t old_sha256 \t new_sha256 \t prev_hash \t entry_hash
//
// entry_hash = SHA-256("fimd-log-v1" || every other field, newline-joined).
// Each record therefore commits to its predecessor, so editing, deleting or
// reordering any record breaks every hash after it. Truncating the tail is not
// detectable from the file alone; compare head() / count against a copy held
// off-box (see `fimd head` and `fimd verify-log --expect-head`).
class ChainLog {
 public:
  explicit ChainLog(std::string path) : path_(std::move(path)) {}
  ~ChainLog();
  ChainLog(const ChainLog&) = delete;
  ChainLog& operator=(const ChainLog&) = delete;

  // Opens (creating 0600), takes an exclusive flock, verifies the existing
  // chain end to end and positions at its head. Fails if the chain is broken.
  bool open(std::string& err);

  bool append(const std::string& kind, const std::string& path, const std::string& old_hash,
              const std::string& new_hash, std::string& err);

  const std::string& head() const { return head_; }
  uint64_t count() const { return seq_; }

  // Standalone verification of a log file. On success sets head and count.
  static bool verify(const std::string& path, std::string& head, uint64_t& count, std::string& err);

  static std::string genesis();

 private:
  std::string path_;
  int fd_ = -1;
  std::string head_;
  uint64_t seq_ = 0;
};

}  // namespace fimd
