#pragma once
#include <sys/types.h>

#include <string>
#include <vector>

namespace fimd {

// Percent-escape '%', control characters and DEL so that a path is a single
// printable, tab- and newline-free token. unesc() is the exact inverse.
std::string esc(const std::string& s);
std::string unesc(const std::string& s);

bool read_file(const std::string& path, std::string& out);

// Write to a sibling temp file (O_EXCL|O_NOFOLLOW), fsync, then rename over
// the destination so readers never observe a half-written file.
bool write_file_atomic(const std::string& path, const std::string& data, mode_t mode = 0644);

std::vector<std::string> split(const std::string& s, char sep);

// RFC 3339 UTC timestamp with millisecond precision.
std::string utc_now();

// True if p equals prefix or lies beneath it (component-wise, not textual).
bool under(const std::string& p, const std::string& prefix);

// Absolute, lexically normalised path with no trailing slash (except "/").
std::string normalize_path(const std::string& p);

}  // namespace fimd
