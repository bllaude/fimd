#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace fimd {

struct Entry {
  char type = 'f';  // 'f' regular file, 'l' symlink (hash is of the link target text)
  uint32_t mode = 0;
  uint32_t uid = 0;
  uint32_t gid = 0;
  uint64_t size = 0;
  std::string sha256;

  bool same_content(const Entry& o) const { return type == o.type && size == o.size && sha256 == o.sha256; }
  bool same_meta(const Entry& o) const { return mode == o.mode && uid == o.uid && gid == o.gid; }
};

using Snapshot = std::map<std::string, Entry>;

struct Scope {
  std::vector<std::string> roots;     // absolute directories
  std::vector<std::string> excludes;  // absolute paths, files or directories

  bool excluded(const std::string& path) const;
};

// Hash one path without following symlinks. Regular files are opened
// O_NOFOLLOW|O_NONBLOCK, type-checked after open, and stat-ed before and after
// hashing so a file changing mid-read is retried instead of recorded torn.
// Returns false for vanished paths and for non-regular, non-symlink objects.
bool hash_path(const std::string& path, Entry& out);

Snapshot scan(const Scope& scope);

struct Baseline {
  Scope scope;
  Snapshot entries;
  std::string created;
  std::string file_sha256;  // digest of the signed manifest bytes, set by load_verified
};

std::string serialize(const Baseline& b);
bool parse(const std::string& text, Baseline& out, std::string& err);

// Write manifest and manifest.sig (raw Ed25519 signature) next to each other.
bool save_signed(const Baseline& b, const std::string& path, const std::string& priv_key, std::string& err);

// Read manifest, verify manifest.sig against the public key, then parse.
// Nothing from the manifest is trusted before the signature has verified.
bool load_verified(const std::string& path, const std::string& pub_key, Baseline& out, std::string& err);

}  // namespace fimd
