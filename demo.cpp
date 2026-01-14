// Build (MSVC):  cl /Zi /Od /EHsc demo.cpp /Fe:demo.exe /link /release
// Build (MinGW): g++ -g -O0 demo.cpp -o demo.exe && strip demo.exe
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#ifdef _MSC_VER
#include <windows.h>
#endif

// Handy payload we keep reusing in calls and casts.
struct Packet {
    uint32_t opcode;
    uint32_t length;
    char     payload[32];
};

// ---------------------------------------------------------------------------
// Parameter labels + rename/retype at call site (Y on the argument)
// ---------------------------------------------------------------------------
static void analyze_packet(Packet *pkt, int channel, bool verbose) {
    if (!pkt) {
        puts("[analyze_packet] null packet");
        return;
    }
    if (verbose) {
        printf("[analyze_packet] opcode=%u len=%u channel=%d\n",
               pkt->opcode, pkt->length, channel);
    }
}

// ---------------------------------------------------------------------------
// Copy/paste name & type helpers (C / V and Ctrl-Alt-C / Ctrl-Alt-V)
// ---------------------------------------------------------------------------
static void type_handoff_demo() {
    void *raw = std::malloc(sizeof(Packet));
    std::memset(raw, 0, sizeof(Packet));

    // Place the cursor on raw, press Ctrl-Alt-C to copy Packet,
    // then move to typed and press Ctrl-Alt-V to paste the type.
    Packet *typed = reinterpret_cast<Packet *>(raw);
    typed->opcode = 0x33;
    typed->length = 4;

    std::free(raw);
}

// ---------------------------------------------------------------------------
// Vtable navigation:
// - Double-click a vtable entry (e.g., ops->start) to jump to the implementation.
// - When there is no exact name match, HappyIDA shows a partial-match candidate list.
//   This helps when base/derived classes share member names but differ by prefixes/suffixes.
// ---------------------------------------------------------------------------
struct DeviceOps {
    void (*start)(Packet *);
    int  (*process)(Packet *, int);
    void (*stop)(Packet *);
};

static void base_start(Packet *pkt)   { printf("[base_start] %u\n", pkt->opcode); }
static int  process(Packet *pkt, int slot) {
    printf("[process] slot=%d len=%u\n", slot, pkt->length);
    return pkt->payload[slot % sizeof(pkt->payload)];
}
static void base_stop(Packet *pkt)    { printf("[base_stop] %u\n", pkt->opcode); }

static void pro_start(Packet *pkt)    { printf("[pro_start] %u\n", pkt->opcode); }
static int  pro_process(Packet *pkt, int slot) {
    printf("[pro_process] slot=%d len=%u\n", slot, pkt->length);
    return pkt->payload[(slot + 1) % sizeof(pkt->payload)];
}
static void pro_stop(Packet *pkt)     { printf("[pro_stop] %u\n", pkt->opcode); }

static DeviceOps g_base_ops = { base_start, process, base_stop };
static DeviceOps g_pro_ops  = { pro_start,  pro_process,  pro_stop  };

static void drive_device(DeviceOps *ops, Packet *pkt) {
    ops->start(pkt);                     // exact matches do not exist; chooser offers base_start/pro_start
    int val = ops->process(pkt, 3);      // chooser shows process/pro_process when double-clicked
    printf("[drive_device] sample=%d\n", val);
    ops->stop(pkt);                      // chooser shows base_stop/pro_stop
}

// ---------------------------------------------------------------------------
// SEH highlighting/rebuild (__try / __except). Falls back to C++ exceptions.
// ---------------------------------------------------------------------------
static int seh_probe(int value) {
#ifdef _MSC_VER
    __try {
        if (value == 0) {
            RaiseException(0xE0FFEE00, 0, 0, nullptr);
        }
        return 1;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
#else
    try {
        if (value == 0) {
            throw std::runtime_error("probe");
        }
        return 1;
    } catch (...) {
        return -1;
    }
#endif
}

// ---------------------------------------------------------------------------
// Rust string pretty-print trigger (rodata contains "rustc-").
// ---------------------------------------------------------------------------
static const char *kRustBanner = "rustc-1.75.0 synthetic binary for HappyIDA";

int main() {
    Packet *pkt = new Packet{};
    std::strcpy(pkt->payload, "IDA rules");
    pkt->opcode = 0xABCD;
    pkt->length = std::strlen(pkt->payload);

    // Parameter labels + inline rename/retype (press Y on the argument).
    analyze_packet(pkt, /*channel*/ 7, /*verbose*/ true);

    // Clipboard helpers: copy/paste name and type on pkt/payload.
    type_handoff_demo();

    // Vtable navigation: double-click start/process/stop in pseudocode to jump or pick from candidates.
    DeviceOps *ops = (pkt->opcode & 1) ? &g_pro_ops : &g_base_ops;
    drive_device(ops, pkt);

    // SEH coloring/rebuild demo.
    int probe = seh_probe(pkt->length == 0 ? 0 : 1);
    printf("[seh_probe] result=%d\n", probe);

    // Keep the rust banner referenced so it survives the optimizer.
    if (kRustBanner[0] == 'r') {
        puts(kRustBanner);
    }

    delete pkt;

    return 0;
}
