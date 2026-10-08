// Offline signature verification: maps a DSCS executable as an image and checks that every
// signature in include/dscs/signatures.inc resolves uniquely to its reference RVA.
//
//   sigtest <DigimonStoryCS.unpacked.exe>   -> exit 0 when all symbols resolve to the expected RVAs
//   sigtest <Digimon Story CS.exe>          -> SteamStub-packed exe: only imports are checkable
//
// Build: cmake -DDSCSML_BUILD_TESTS=ON ...  (target `sigtest`, no Boost needed)
#include "dscs/Symbols.h"
#include "modloader/sigscan.h"

#include <Windows.h>

#include <cstdio>

int main(int argc, char** argv)
{
    if (argc != 2 && argc != 3)
    {
        std::printf("usage: %s <path to DSCS exe> [pattern]\n", argv[0]);
        return 2;
    }

    // Image-layout mapping without running any code from the target.
    HMODULE mapped = LoadLibraryExA(argv[1], nullptr, LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE);
    if (!mapped)
    {
        std::printf("failed to map %s (error %lu)\n", argv[1], GetLastError());
        return 2;
    }
    // LoadLibraryEx tags data/resource mappings in the low bits of the handle.
    auto base = reinterpret_cast<char*>(reinterpret_cast<uintptr_t>(mapped) & ~static_cast<uintptr_t>(3));
    modloader::sigscan::setModule(base);

    if (argc == 3)
    { // probe mode: sigtest <exe> "<pattern>"
        modloader::sigscan::Pattern pattern;
        if (!modloader::sigscan::parsePattern(argv[2], pattern))
        {
            std::printf("invalid pattern\n");
            return 2;
        }
        for (char* hit : modloader::sigscan::findAll(pattern, 16))
            std::printf("hit at RVA 0x%llX\n", static_cast<unsigned long long>(hit - base));
        return 0;
    }

    uint32_t errors = 0;
    dscs::symbols::resolveAll(
        [&](bool isError, const std::string& message)
        {
            std::printf("%s %s\n", isError ? "MISSING " : "MISMATCH", message.c_str());
            errors++;
        });

    uint32_t ok = 0;
    for (uint32_t i = 0; i < static_cast<uint32_t>(dscs::symbols::Sym::Count); i++)
    {
        const auto sym = static_cast<dscs::symbols::Sym>(i);
        if (char* address = dscs::symbols::get(sym))
            if (static_cast<uint64_t>(address - base) == dscs::symbols::expectedRva(sym)) ok++;
    }

    std::printf("%u/%u symbols resolved to their reference RVA, %u problem(s)\n",
                ok,
                static_cast<uint32_t>(dscs::symbols::Sym::Count),
                errors);
    return errors == 0 ? 0 : 1;
}
