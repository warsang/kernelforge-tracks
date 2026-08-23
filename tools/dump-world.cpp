/**
 * tools/dump-world.cpp — extract a "kernel world snapshot" (processes,
 * tokens, loaded modules) from a Windows x64 kernel dump using
 * 0vercl0k/kdmp-parser. Output feeds ntsim's real-dump scenario mode.
 *
 * Struct offsets are passed in from the Vergilius tables (kept out of this
 * binary so it stays layout-agnostic):
 *
 *   dump-world <dump.dmp> <out.json> \
 *     --links 0x448 --pid 0x440 --name 0x5a8 --token 0x4b8 [--prot 0x48a] \
 *     --kldr-links 0x30 --kldr-base 0x30? ... (see runner script)
 */

#include <kdmp-parser.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

static const uint64_t FAST_REF_MASK = ~0xfull;

struct Args {
  std::string dump, out;
  uint64_t links = 0, pid = 0, name = 0, token = 0, prot = ~0ull;
  uint64_t kldrLinks = 0, kldrBase = 0, kldrSize = 0, kldrFull = 0, kldrBaseName = 0;
  uint64_t procHead = 0, modHead = 0;
  uint64_t maxProcs = 64, maxMods = 256;
};

int main(int argc, char **argv) {
  Args a;
  std::map<std::string, uint64_t *> numArgs = {
    {"--links", &a.links}, {"--pid", &a.pid}, {"--name", &a.name},
    {"--token", &a.token}, {"--prot", &a.prot},
    {"--kldr-links", &a.kldrLinks}, {"--kldr-base", &a.kldrBase},
    {"--proc-head", &a.procHead}, {"--mod-head", &a.modHead},
    {"--kldr-size", &a.kldrSize}, {"--kldr-full", &a.kldrFull},
    {"--max-procs", &a.maxProcs}, {"--max-mods", &a.maxMods},
  };
  for (int i = 1; i < argc; i++) {
    const std::string arg = argv[i];
    if (arg == "--dump") a.dump = argv[++i];
    else if (arg == "--out") a.out = argv[++i];
    else if (numArgs.count(arg)) *numArgs[arg] = strtoull(argv[++i], nullptr, 0);
  }
  if (a.dump.empty() || a.out.empty() || !a.links || !a.pid || !a.token ||
      !a.procHead || !a.modHead || !a.kldrBase || !a.kldrFull) {
    fprintf(stderr, "missing required args: links=%llu pid=%llu token=%llu procHead=%llx modHead=%llx kldrLinks=%llu base=%llu full=%llu\n",
      (unsigned long long)a.links,(unsigned long long)a.pid,(unsigned long long)a.token,
      (unsigned long long)a.procHead,(unsigned long long)a.modHead,
      (unsigned long long)a.kldrLinks,(unsigned long long)a.kldrBase,(unsigned long long)a.kldrFull);
    return 1;
  }

  kdmpparser::KernelDumpParser Parser;
  if (!Parser.Parse(a.dump.c_str())) {
    fprintf(stderr, "Parse failed\n");
    return 1;
  }
  const uint64_t DTB = Parser.GetDirectoryTableBase();
  fprintf(stderr, "[+] dtb=0x%llx\n", (unsigned long long)DTB);

  auto virtRead = [&](uint64_t va, void *dst, size_t len) -> bool {
    uint8_t *d = (uint8_t *)dst;
    size_t done = 0;
    while (done < len) {
      const uint64_t cur = va + done;
      const uint64_t pageVa = cur & ~0xfffull;
      const uint8_t *page = Parser.GetVirtualPage(pageVa, DTB);
      if (!page) return false;
      const size_t inPage = (size_t)(cur - pageVa);
      const size_t chunk = std::min(len - done, (size_t)0x1000 - inPage);
      memcpy(d + done, page + inPage, chunk);
      done += chunk;
    }
    return true;
  };
  auto virtU64 = [&](uint64_t va, uint64_t *out) {
    return virtRead(va, out, 8);
  };

  // ---- processes ----
  struct Proc { uint64_t eproc; uint64_t pid; std::string name;
                uint64_t tokenRaw, tokenTarget; std::string tokenHex;
                int protByte; bool hasProt; };
  std::vector<Proc> procs;
  {
    uint64_t headEnt;
    if (!virtRead(a.links ? 0 : 0, &headEnt, 0)) {}
    // caller passes PsActiveProcessHead via --links as the HEAD address itself
  }

  const uint64_t headAddr = a.procHead;
  uint64_t flink = 0;
  if (!virtRead(headAddr, &flink, 8)) { fprintf(stderr, "read head failed\n"); return 1; }
  const uint64_t headEntry = headAddr;
  int guard = (int)a.maxProcs + 16;
  while (flink && flink != headEntry && guard-- > 0) {
    const uint64_t eproc = flink - a.links;
    Proc p{};
    p.eproc = eproc;
    if (!virtRead(eproc + a.pid, &p.pid, 8)) break;
    char nm[16] = {};
    virtRead(eproc + a.name, nm, 15);
    p.name = nm;
    virtRead(eproc + a.token, &p.tokenRaw, 8);
    p.tokenTarget = p.tokenRaw & FAST_REF_MASK;
    if (p.tokenTarget) {
      uint8_t blob[0x28];
      memset(blob, 0, sizeof blob);
      if (virtRead(p.tokenTarget, blob, sizeof blob))
        for (int i = 0; i < (int)sizeof blob; i++) {
          char tmp[3]; snprintf(tmp, sizeof tmp, "%02x", blob[i]);
          p.tokenHex += tmp;
        }
    }
    if (a.prot != ~0ull) {
      uint8_t pb = 0;
      if (virtRead(eproc + a.prot, &pb, 1)) { p.protByte = pb; p.hasProt = true; }
    }
    procs.push_back(p);
    if (!virtRead(flink, &flink, 8)) break;
  }

  // ---- modules ----
  struct Mod { uint64_t base; uint64_t size; std::string full, baseName; };
auto readUs = [&](uint64_t va, std::string &out) {
      uint16_t len = 0; uint64_t buf = 0;
      if (!virtRead(va, &len, 2)) return;
      if (!virtRead(va + 8, &buf, 8)) return;
      if (!len || len >= 4096 || !buf) return;
      std::vector<char> b(len);
      if (virtRead(buf, b.data(), len)) out.assign(b.data(), b.data() + len / 2);
};
  std::vector<Mod> mods;
  {
    const uint64_t headAddrM = a.modHead;
    uint64_t flinkM = 0;
    if (!virtRead(headAddrM, &flinkM, 8)) { fprintf(stderr, "read mod head failed\n"); return 1; }
    int guard = (int)a.maxMods + 16;
    while (flinkM && flinkM != headAddrM && guard-- > 0) {
      const uint64_t ent = flinkM - a.kldrLinks;
      Mod m{};
      virtRead(ent + a.kldrBase, &m.base, 8);
      if (a.kldrSize) virtRead(ent + a.kldrSize, &m.size, 8);
      readUs(ent + a.kldrFull, m.full);
      if (a.kldrBaseName) readUs(ent + a.kldrBaseName, m.baseName);
      mods.push_back(m);
      if (!virtRead(flinkM, &flinkM, 8)) break;
    }
  }

  // ---- emit ----
  FILE *f = fopen(a.out.c_str(), "w");
  fprintf(f, "{\n  \"meta\": {\n");
  fprintf(f, "    \"source\": \"KDemu mem.dmp\",\n");
  fprintf(f, "    \"format\": \"PAGEDU64\",\n");
  fprintf(f, "    \"directoryTableBase\": \"0x%llx\",\n", (unsigned long long)DTB);
  fprintf(f, "    \"processCount\": %zu,\n", procs.size());
  fprintf(f, "    \"moduleCount\": %zu\n", mods.size());
  fprintf(f, "  },\n  \"processes\": [\n");
  for (size_t i = 0; i < procs.size(); i++) {
    const auto &p = procs[i];
    fprintf(f, "    { \"pid\": %llu, \"name\": \"%s\", \"eprocess\": \"0x%llx\", ",
            (unsigned long long)p.pid, p.name.c_str(), (unsigned long long)p.eproc);
    if (p.hasProt) fprintf(f, "\"protectionByte\": %d, ", p.protByte);
    fprintf(f, "\"token\": { \"raw\": \"0x%llx\", \"target\": \"0x%llx\"",
            (unsigned long long)p.tokenRaw, (unsigned long long)p.tokenTarget);
    if (!p.tokenHex.empty()) fprintf(f, ", \"blob256\": \"%s\"", p.tokenHex.c_str());
    fprintf(f, " } }%s\n", i + 1 < procs.size() ? "," : "");
  }
  fprintf(f, "  ],\n  \"modules\": [\n");
  for (size_t i = 0; i < mods.size(); i++) {
    const auto &m = mods[i];
    std::string esc;
    for (char ch : m.full) {
      if (ch == '"') esc += "\\\"";
      else if (ch == '\\') esc += "\\\\";
      else if ((unsigned char)ch >= 32) esc += ch;
    }
    std::string escBase;
    for (char ch : m.baseName) {
      if (ch == '"') escBase += "\\\"";
      else if (ch == '\\') escBase += "\\\\";
      else if ((unsigned char)ch >= 32) escBase += ch;
    }
    fprintf(f, "    { \"base\": \"0x%llx\", \"sizeOfImage\": %llu, \"baseDllName\": \"%s\", \"fullDllName\": \"%s\" }%s\n",
            (unsigned long long)m.base, (unsigned long long)m.size,
            escBase.c_str(), esc.c_str(), i + 1 < mods.size() ? "," : "");
  }
  fprintf(f, "  ]\n}\n");
  fclose(f);
  fprintf(stderr, "[+] wrote %s (%zu procs, %zu mods)\n", a.out.c_str(), procs.size(), mods.size());
  return 0;
}
