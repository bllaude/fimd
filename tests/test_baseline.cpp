// Unit tests for src/baseline.cpp: hashing, scanning, manifest (de)serialisation
// and the signed save/load path.
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <string>

#include "baseline.hpp"
#include "crypto.hpp"
#include "test_framework.hpp"
#include "util.hpp"

using namespace fimd;

namespace {

constexpr const char* kEmptySha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
constexpr const char* kHelloSha =
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";  // sha256("hello\n")

void put(const std::string& path, const std::string& data) {
  std::ofstream os(path, std::ios::binary);
  os << data;
}

Baseline make_baseline() {
  Baseline b;
  b.created = "2026-10-27T00:00:00.000Z";
  return b;
}

Entry file_entry(uint32_t mode, uint64_t size, const std::string& sha) {
  Entry e;
  e.type = 'f';
  e.mode = mode;
  e.uid = 0;
  e.gid = 0;
  e.size = size;
  e.sha256 = sha;
  return e;
}

}  // namespace

TEST(Baseline, HashPathRegularFileMatchesKnownDigest) {
  tf::TempDir tmp("fimd_base_hash");
  ASSERT_TRUE(tmp.ok());
  const std::string p = tmp / "hello.txt";
  put(p, "hello\n");

  Entry e;
  ASSERT_TRUE(hash_path(p, e));
  EXPECT_EQ(std::string(1, e.type), "f");
  EXPECT_EQ(e.sha256, kHelloSha);
  EXPECT_EQ(e.size, static_cast<unsigned long long>(6));

  struct stat st;
  ASSERT_TRUE(::stat(p.c_str(), &st) == 0);
  EXPECT_EQ(static_cast<long long>(e.mode), static_cast<long long>(st.st_mode & 07777));
  EXPECT_EQ(static_cast<long long>(e.uid), static_cast<long long>(st.st_uid));
  EXPECT_EQ(static_cast<long long>(e.gid), static_cast<long long>(st.st_gid));
}

TEST(Baseline, HashPathEmptyFile) {
  tf::TempDir tmp("fimd_base_empty");
  ASSERT_TRUE(tmp.ok());
  const std::string p = tmp / "zero";
  put(p, "");
  Entry e;
  ASSERT_TRUE(hash_path(p, e));
  EXPECT_EQ(e.sha256, kEmptySha);
  EXPECT_EQ(e.size, static_cast<unsigned long long>(0));
}

TEST(Baseline, HashPathSymlinkHashesTargetTextWithoutFollowing) {
  tf::TempDir tmp("fimd_base_link");
  ASSERT_TRUE(tmp.ok());
  put(tmp / "target", "content\n");
  const std::string link = tmp / "link";
  ASSERT_TRUE(::symlink("./target", link.c_str()) == 0);

  Entry e;
  ASSERT_TRUE(hash_path(link, e));
  EXPECT_EQ(std::string(1, e.type), "l");
  EXPECT_EQ(e.size, static_cast<unsigned long long>(8));  // strlen("./target")
  EXPECT_EQ(e.sha256, sha256_hex("./target"));             // digest of the target TEXT

  // A dangling symlink still hashes: only the stored text matters.
  const std::string dangle = tmp / "dangle";
  ASSERT_TRUE(::symlink("/nowhere/absolute", dangle.c_str()) == 0);
  Entry d;
  ASSERT_TRUE(hash_path(dangle, d));
  EXPECT_EQ(std::string(1, d.type), "l");
  EXPECT_EQ(d.sha256, sha256_hex("/nowhere/absolute"));
}

TEST(Baseline, HashPathRejectsMissingPathsAndNonRegularObjects) {
  tf::TempDir tmp("fimd_base_reject");
  ASSERT_TRUE(tmp.ok());
  Entry e;
  EXPECT_FALSE(hash_path(tmp / "ghost", e));           // vanished path
  EXPECT_FALSE(hash_path(tmp.path() + "/", e));        // directory itself
  const std::string fifo = tmp / "pipe";
  ASSERT_TRUE(::mkfifo(fifo.c_str(), 0644) == 0);
  EXPECT_FALSE(hash_path(fifo, e));                    // FIFO is not hashable
}

TEST(Baseline, ScopeExclusionIsComponentWiseAndRecursive) {
  Scope s;
  s.roots = {"/etc"};
  s.excludes = {"/etc/mtab", "/etc/ssl/certs"};
  EXPECT_TRUE(s.excluded("/etc/mtab"));
  EXPECT_TRUE(s.excluded("/etc/ssl/certs"));
  EXPECT_TRUE(s.excluded("/etc/ssl/certs/pem/ca.crt"));  // inside an excluded dir
  EXPECT_FALSE(s.excluded("/etc/passwd"));
  EXPECT_FALSE(s.excluded("/etc/mtab.bak"));             // textual prefix is not enough
  EXPECT_FALSE(s.excluded("/etcetera/mtab"));
  Scope empty;
  EXPECT_FALSE(empty.excluded("/anything"));
}

TEST(Baseline, ScanWalksRecursivelyAppliesExclusionsAndSkipsFifos) {
  tf::TempDir tmp("fimd_base_scan");
  ASSERT_TRUE(tmp.ok());
  const std::string root = tmp / "tree";
  ::mkdir(root.c_str(), 0755);
  ::mkdir((root + "/sub").c_str(), 0755);
  ::mkdir((root + "/skipme").c_str(), 0755);
  put(root + "/a.txt", "hello\n");
  put(root + "/sub/b.txt", "beta\n");
  put(root + "/skipme/c.txt", "gamma\n");
  ASSERT_TRUE(::symlink("a.txt", (root + "/link").c_str()) == 0);
  ASSERT_TRUE(::mkfifo((root + "/pipe").c_str(), 0644) == 0);

  Scope s;
  s.roots = {root};
  s.excludes = {root + "/skipme"};
  Snapshot snap = scan(s);

  EXPECT_EQ(snap.size(), static_cast<unsigned long>(3));  // a.txt, sub/b.txt, link
  ASSERT_TRUE(snap.count(root + "/a.txt") == 1);
  EXPECT_EQ(snap[root + "/a.txt"].sha256, kHelloSha);
  ASSERT_TRUE(snap.count(root + "/sub/b.txt") == 1);
  EXPECT_EQ(std::string(1, snap[root + "/sub/b.txt"].type), "f");
  ASSERT_TRUE(snap.count(root + "/link") == 1);
  EXPECT_EQ(std::string(1, snap[root + "/link"].type), "l");
  EXPECT_TRUE(snap.count(root + "/skipme/c.txt") == 0);
  EXPECT_TRUE(snap.count(root + "/pipe") == 0);
}

TEST(Baseline, SerializeProducesCanonicalHeaderLayout) {
  Baseline b = make_baseline();
  b.scope.roots = {"/tree"};
  b.scope.excludes = {"/tree/skip"};
  b.entries["/tree/a.txt"] = file_entry(0644, 6, kHelloSha);

  const std::string s = serialize(b);
  const std::string expect =
      "fimd-baseline v1\n"
      "created\t2026-10-27T00:00:00.000Z\n"
      "root\t/tree\n"
      "exclude\t/tree/skip\n"
      "f\t644\t0\t0\t6\t" +
      kHelloSha + "\t/tree/a.txt\n";
  EXPECT_EQ(s, expect);
}

TEST(Baseline, SerializeEscapesPathsSortsThemAndPrintsOctalMode) {
  Baseline b = make_baseline();
  b.scope.roots = {"/we" "\t" "ird"};
  b.entries["/dir/z.txt"] = file_entry(0755, 1, "x");
  b.entries["/dir/a.txt"] = file_entry(0600, 1, "y");
  b.entries["/dir/tab\there"] = file_entry(01777, 1, "z");

  const std::string s = serialize(b);
  EXPECT_TRUE(s.find("root\t/we%09ird\n") != std::string::npos);   // tab escaped in roots
  EXPECT_TRUE(s.find("\t/dir/tab%09here\n") != std::string::npos); // tab escaped in paths
  EXPECT_TRUE(s.find("f\t1777\t") != std::string::npos);            // octal, no leading zero
  // Sorted map order: a before z.
  size_t pa = s.find("/dir/a.txt");
  size_t pz = s.find("/dir/z.txt");
  EXPECT_TRUE(pa != std::string::npos && pz != std::string::npos && pa < pz);
}

TEST(Baseline, ParseRoundtripsSerializeIncludingNastyPaths) {
  Baseline b = make_baseline();
  b.scope.roots = {"/root with space/we" "\t" "ird"};
  b.scope.excludes = {"/root with space/we" "\t" "ird/ex%clude"};
  Entry f = file_entry(0644, 6, kHelloSha);
  b.entries["/root with space/we" "\t" "ird/a.txt"] = f;
  Entry l;
  l.type = 'l';
  l.mode = 0777;
  l.uid = 1000;
  l.gid = 1001;
  l.size = 5;
  l.sha256 = sha256_hex("../x");
  b.entries["/sym/l"] = l;

  Baseline out;
  std::string err;
  ASSERT_TRUE(parse(serialize(b), out, err));
  EXPECT_EQ(out.created, b.created);
  ASSERT_TRUE(out.scope.roots.size() == 1);
  EXPECT_EQ(out.scope.roots[0], b.scope.roots[0]);
  ASSERT_TRUE(out.scope.excludes.size() == 1);
  EXPECT_EQ(out.scope.excludes[0], b.scope.excludes[0]);
  EXPECT_EQ(out.entries.size(), static_cast<unsigned long>(2));
  EXPECT_TRUE(out.entries.count(b.entries.begin()->first) == 1);
  const Entry& re = out.entries[b.entries.begin()->first];
  EXPECT_EQ(re.mode, f.mode);
  EXPECT_EQ(re.size, f.size);
  EXPECT_EQ(re.sha256, f.sha256);
  const Entry& rl = out.entries["/sym/l"];
  EXPECT_EQ(std::string(1, rl.type), "l");
  EXPECT_EQ(static_cast<long long>(rl.mode), static_cast<long long>(0777));
  EXPECT_EQ(static_cast<long long>(rl.uid), 1000);
  EXPECT_EQ(static_cast<long long>(rl.gid), 1001);
}

TEST(Baseline, ParseRejectsBadInput) {
  Baseline out;
  std::string err;

  EXPECT_FALSE(parse("", out, err));                                   // no header
  EXPECT_FALSE(parse("not a baseline\nroot\t/x\n", out, err));         // wrong magic
  EXPECT_TRUE(err.find("header") != std::string::npos);

  EXPECT_FALSE(parse("fimd-baseline v1\ncreated\tX\n", out, err));     // no roots
  EXPECT_TRUE(err.find("no roots") != std::string::npos);

  EXPECT_FALSE(parse("fimd-baseline v1\nroot\t/x\nbogus\tdata\n", out, err));
  EXPECT_TRUE(err.find("unrecognised") != std::string::npos);

  EXPECT_FALSE(parse("fimd-baseline v1\nroot\t/x\nf\tzzz\t0\t0\t0\t" +
                     std::string(64, 'a') + "\t/p\n", out, err));       // bad octal mode
  EXPECT_TRUE(err.find("bad mode") != std::string::npos);

  EXPECT_FALSE(parse("fimd-baseline v1\nroot\t/x\nf\t644\t-1\t0\t0\t" +
                     std::string(64, 'a') + "\t/p\n", out, err));       // negative uid
  EXPECT_TRUE(err.find("bad uid") != std::string::npos);

  EXPECT_FALSE(parse("fimd-baseline v1\nroot\t/x\nf\t644\t0\t0\tnotanumber\t" +
                     std::string(64, 'a') + "\t/p\n", out, err));       // bad size
  EXPECT_TRUE(err.find("bad size") != std::string::npos);

  EXPECT_FALSE(parse("fimd-baseline v1\nroot\t/x\nf\t644\t0\t0\t1\tdeadbeef\t/p\n", out, err));
  EXPECT_TRUE(err.find("bad digest") != std::string::npos);             // short digest

  EXPECT_FALSE(parse("fimd-baseline v1\nroot\t/x\nd\t644\t0\t0\t1\t" +
                     std::string(64, 'a') + "\t/p\n", out, err));       // unknown type letter

  // Trailing newline (empty final line) is tolerated.
  EXPECT_TRUE(parse("fimd-baseline v1\nroot\t/x\n", out, err));
}

TEST(Baseline, SaveSignedAndLoadVerifiedRoundtrip) {
  tf::TempDir tmp("fimd_base_signed");
  ASSERT_TRUE(tmp.ok());
  std::string err;
  ASSERT_TRUE(generate_keypair(tmp / "k.pem", tmp / "k.pub", err));

  Baseline b = make_baseline();
  b.scope.roots = {tmp.path()};
  b.entries[tmp / "note"] = file_entry(0644, 6, kHelloSha);
  ASSERT_TRUE(save_signed(b, tmp / "base", tmp / "k.pem", err);

  Baseline got;
  ASSERT_TRUE(load_verified(tmp / "base", tmp / "k.pub", got, err);
  EXPECT_EQ(got.created, b.created);
  EXPECT_EQ(got.entries.size(), static_cast<unsigned long>(1));
  EXPECT_EQ(got.file_sha256, sha256_hex(serialize(b)));  // binds to exact manifest bytes
}

TEST(Baseline, LoadVerifiedRejectsEditedManifest) {
  tf::TempDir tmp("fimd_base_edit");
  ASSERT_TRUE(tmp.ok());
  std::string err;
  ASSERT_TRUE(generate_keypair(tmp / "k.pem", tmp / "k.pub", err));

  Baseline b = make_baseline();
  b.scope.roots = {"/orig"};
  ASSERT_TRUE(save_signed(b, tmp / "base", tmp / "k.pem", err));

  // Attacker edits the manifest but cannot re-sign it.
  std::string text;
  ASSERT_TRUE(read_file(tmp / "base", text));
  text += "f\t644\t0\t0\t1\t" + std::string(64, 'a') + "\t/evil/added\n";
  ASSERT_TRUE(write_file_atomic(tmp / "base", text, 0644));

  Baseline got;
  EXPECT_FALSE(load_verified(tmp / "base", tmp / "k.pub", got, err));
  EXPECT_TRUE(err.find("signature") != std::string::npos);
}

TEST(Baseline, LoadVerifiedRejectsWrongKeyMissingSigAndGarbageSig) {
  tf::TempDir tmp("fimd_base_wrongkey");
  ASSERT_TRUE(tmp.ok());
  std::string err;
  ASSERT_TRUE(generate_keypair(tmp / "a.pem", tmp / "a.pub", err));
  ASSERT_TRUE(generate_keypair(tmp / "b.pem", tmp / "b.pub", err));

  Baseline b = make_baseline();
  b.scope.roots = {"/x"};
  ASSERT_TRUE(save_signed(b, tmp / "base", tmp / "a.pem", err));

  Baseline got;
  EXPECT_FALSE(load_verified(tmp / "base", tmp / "b.pub", got, err));  // other keypair

  ASSERT_TRUE(::unlink((tmp.path() + "/base.sig").c_str()) == 0);
  EXPECT_FALSE(load_verified(tmp / "base", tmp / "a.pub", got, err));  // missing signature

  ASSERT_TRUE(write_file_atomic(tmp / "base.sig", std::string(64, 'Z'), 0644));
  EXPECT_FALSE(load_verified(tmp / "base", tmp / "a.pub", got, err));  // garbage signature

  EXPECT_FALSE(load_verified(tmp / "nonexistent", tmp / "a.pub", got, err));  // missing manifest
}

TEST(Baseline, EntryContentAndMetaComparison) {
  Entry a = file_entry(0644, 6, kHelloSha);
  Entry b = a;
  EXPECT_TRUE(a.same_content(b));
  EXPECT_TRUE(a.same_meta(b));

  b.sha256 = kEmptySha;  // content changed, metadata identical
  EXPECT_FALSE(a.same_content(b));
  EXPECT_TRUE(a.same_meta(b));

  Entry c = a;
  c.mode = 0600;  // chmod only: same content, different meta (ATTRIB case)
  EXPECT_TRUE(a.same_content(c));
  EXPECT_FALSE(a.same_meta(c));

  Entry d = a;
  d.uid = 1;
  EXPECT_FALSE(a.same_meta(d));
  Entry e = a;
  e.gid = 1;
  EXPECT_FALSE(a.same_meta(e));

  Entry link = a;
  link.type = 'l';  // file replaced by a symlink of the same size/hash is content change
  EXPECT_FALSE(a.same_content(link));
}
