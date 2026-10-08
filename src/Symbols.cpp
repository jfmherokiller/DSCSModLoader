#include "dscs/Symbols.h"

#include "modloader/sigscan.h"

#include <array>
#include <cstring>
#include <format>

namespace dscs::symbols
{
    namespace
    {
        enum class Kind
        {
            Code,
            CallTarget,
            RipRelative,
            Import
        };

        struct Entry
        {
            const char* name;
            Kind kind;
            const char* pattern; // or dll for Import
            const char* function; // Import only
            int32_t offset;
            int32_t dispOffset;
            int32_t insnLength;
            uint64_t expectedRva;
        };

        constexpr Entry ENTRIES[] = {
#define SIG_CODE(name, pattern, offset, rva) { #name, Kind::Code, pattern, nullptr, offset, 0, 0, rva },
#define SIG_CALLTARGET(name, pattern, offset, rva) { #name, Kind::CallTarget, pattern, nullptr, offset, 1, 5, rva },
#define SIG_RIPREL(name, pattern, offset, disp, len, rva) { #name, Kind::RipRelative, pattern, nullptr, offset, disp, len, rva },
#define SIG_IMPORT(name, dll, function, rva) { #name, Kind::Import, dll, function, 0, 0, 0, rva },
#include "dscs/signatures.inc"
#undef SIG_CODE
#undef SIG_CALLTARGET
#undef SIG_RIPREL
#undef SIG_IMPORT
        };
        static_assert(std::size(ENTRIES) == static_cast<std::size_t>(Sym::Count));

        std::array<char*, static_cast<std::size_t>(Sym::Count)> g_addresses{};
        bool g_resolved = false;

        char* resolveOne(const Entry& entry)
        {
            using namespace modloader::sigscan;

            if (entry.kind == Kind::Import)
                return reinterpret_cast<char*>(findImportSlot(entry.pattern, entry.function));

            char* hit = findUnique(entry.pattern);
            if (!hit) return nullptr;
            char* insn = hit + entry.offset;

            switch (entry.kind)
            {
                case Kind::Code: return insn;
                case Kind::CallTarget:
                    if (static_cast<uint8_t>(insn[0]) != 0xE8) return nullptr;
                    return resolveRel32(insn, entry.dispOffset, entry.insnLength);
                case Kind::RipRelative: return resolveRel32(insn, entry.dispOffset, entry.insnLength);
                default: return nullptr;
            }
        }
    } // namespace

    uint32_t resolveAll(const LogFunction& log)
    {
        uint32_t failed = 0;
        char* base      = modloader::sigscan::moduleBase();

        for (std::size_t i = 0; i < std::size(ENTRIES); i++)
        {
            const auto& entry = ENTRIES[i];
            char* address     = resolveOne(entry);
            g_addresses[i]    = address;

            if (!address)
            {
                failed++;
                if (log) log(true, std::format("signature for '{}' not found", entry.name));
                continue;
            }

            const auto rva = static_cast<uint64_t>(address - base);
            if (log && rva != entry.expectedRva)
                log(false,
                    std::format("'{}' resolved to RVA 0x{:X} (reference build: 0x{:X})", entry.name, rva, entry.expectedRva));
        }

        g_resolved = failed == 0;
        return failed;
    }

    bool isResolved() { return g_resolved; }

    char* get(Sym symbol) { return g_addresses[static_cast<std::size_t>(symbol)]; }

    const char* name(Sym symbol) { return ENTRIES[static_cast<std::size_t>(symbol)].name; }

    uint64_t expectedRva(Sym symbol) { return ENTRIES[static_cast<std::size_t>(symbol)].expectedRva; }
} // namespace dscs::symbols

char* getGameSymbol(const char* name)
{
    using namespace dscs::symbols;
    for (uint32_t i = 0; i < static_cast<uint32_t>(Sym::Count); i++)
        if (std::strcmp(dscs::symbols::name(static_cast<Sym>(i)), name) == 0) return get(static_cast<Sym>(i));
    return nullptr;
}
