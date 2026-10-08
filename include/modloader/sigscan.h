#pragma once
#include <stdint.h>

#include <string>
#include <string_view>
#include <vector>

// Signature (AOB) scanning over the game's main module.
//
// Pattern syntax: space-separated hex bytes, `??` (or `?`) for a wildcard byte,
// e.g. "48 8B 05 ?? ?? ?? ?? 48 85 C0". Only the `.text` section is scanned, which is
// what tools/gen_signatures.py verifies uniqueness against.
//
// NOTE: the shipped exe is SteamStub-encrypted; `.text` is only valid after the
// stub has run (i.e. from SteamAPI_Init onwards). Import lookups work at any time.
namespace modloader::sigscan
{
    struct Pattern
    {
        std::vector<uint8_t> bytes;
        std::vector<bool> mask; // true = must match, false = wildcard
    };

    bool parsePattern(std::string_view text, Pattern& out);

    // Module to scan. Defaults to GetModuleHandle(NULL); overridable for offline tests.
    void setModule(void* moduleBase);
    char* moduleBase();

    // Up to `maxHits` matches inside .text.
    std::vector<char*> findAll(const Pattern& pattern, std::size_t maxHits = 2);

    // The single match, or nullptr if the pattern is invalid, absent or ambiguous.
    char* findUnique(std::string_view pattern);

    // Address of the IAT slot for dll!function, or nullptr.
    void** findImportSlot(const char* dll, const char* function);

    // Target of a rel32 operand: insn + insnLength + *(int32_t*)(insn + dispOffset).
    char* resolveRel32(char* insn, int32_t dispOffset, int32_t insnLength);
} // namespace modloader::sigscan

// Plugin-facing exports.
extern __declspec(dllexport) char* findSignature(const char* pattern);
