#include "modloader/sigscan.h"

#include <Windows.h>

#include <cstring>

namespace modloader::sigscan
{
    namespace
    {
        char* g_module = nullptr;

        int hexValue(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }

        IMAGE_NT_HEADERS64* ntHeaders(char* base)
        {
            auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
            auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
            return nt;
        }

        bool textSection(char*& begin, std::size_t& size)
        {
            char* base = moduleBase();
            auto nt    = ntHeaders(base);
            if (!nt) return false;

            auto section = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++)
            {
                if (std::strncmp(reinterpret_cast<const char*>(section->Name), ".text", IMAGE_SIZEOF_SHORT_NAME) == 0)
                {
                    begin = base + section->VirtualAddress;
                    size  = section->Misc.VirtualSize;
                    return true;
                }
            }
            return false;
        }
    } // namespace

    bool parsePattern(std::string_view text, Pattern& out)
    {
        out.bytes.clear();
        out.mask.clear();

        std::size_t i = 0;
        while (i < text.size())
        {
            if (text[i] == ' ' || text[i] == '\t')
            {
                i++;
                continue;
            }
            if (text[i] == '?')
            {
                out.bytes.push_back(0);
                out.mask.push_back(false);
                i += (i + 1 < text.size() && text[i + 1] == '?') ? 2 : 1;
                continue;
            }
            if (i + 1 >= text.size()) return false;
            const int hi = hexValue(text[i]);
            const int lo = hexValue(text[i + 1]);
            if (hi < 0 || lo < 0) return false;
            out.bytes.push_back(static_cast<uint8_t>(hi << 4 | lo));
            out.mask.push_back(true);
            i += 2;
        }
        return !out.bytes.empty();
    }

    void setModule(void* base) { g_module = static_cast<char*>(base); }

    char* moduleBase()
    {
        if (!g_module) g_module = reinterpret_cast<char*>(GetModuleHandle(NULL));
        return g_module;
    }

    std::vector<char*> findAll(const Pattern& pattern, std::size_t maxHits)
    {
        std::vector<char*> hits;
        char* begin      = nullptr;
        std::size_t size = 0;
        if (pattern.bytes.empty() || !textSection(begin, size) || size < pattern.bytes.size()) return hits;

        // anchor on the first concrete byte to keep the scan fast
        std::size_t anchor = 0;
        while (anchor < pattern.mask.size() && !pattern.mask[anchor])
            anchor++;
        if (anchor == pattern.mask.size()) return hits; // all wildcards

        const auto* data      = reinterpret_cast<const uint8_t*>(begin);
        const std::size_t end = size - pattern.bytes.size();
        const uint8_t first   = pattern.bytes[anchor];

        for (std::size_t pos = 0; pos <= end; pos++)
        {
            const void* found = std::memchr(data + pos + anchor, first, end - pos + 1);
            if (!found) break;
            pos = static_cast<const uint8_t*>(found) - data - anchor;

            bool match = true;
            for (std::size_t k = 0; k < pattern.bytes.size(); k++)
            {
                if (pattern.mask[k] && data[pos + k] != pattern.bytes[k])
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                hits.push_back(begin + pos);
                if (hits.size() >= maxHits) break;
            }
        }
        return hits;
    }

    char* findUnique(std::string_view text)
    {
        Pattern pattern;
        if (!parsePattern(text, pattern)) return nullptr;
        auto hits = findAll(pattern, 2);
        return hits.size() == 1 ? hits[0] : nullptr;
    }

    void** findImportSlot(const char* dll, const char* function)
    {
        char* base = moduleBase();
        auto nt    = ntHeaders(base);
        if (!nt) return nullptr;

        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (dir.VirtualAddress == 0) return nullptr;

        for (auto desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress); desc->Name; desc++)
        {
            if (_stricmp(base + desc->Name, dll) != 0) continue;

            // OriginalFirstThunk holds the names; FirstThunk is the IAT (overwritten with addresses).
            const auto lookupRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            auto lookup          = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + lookupRva);
            auto iat             = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + desc->FirstThunk);

            for (; lookup->u1.AddressOfData; lookup++, iat++)
            {
                if (IMAGE_SNAP_BY_ORDINAL64(lookup->u1.Ordinal)) continue;
                auto byName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + lookup->u1.AddressOfData);
                if (std::strcmp(reinterpret_cast<const char*>(byName->Name), function) == 0)
                    return reinterpret_cast<void**>(&iat->u1.Function);
            }
        }
        return nullptr;
    }

    char* resolveRel32(char* insn, int32_t dispOffset, int32_t insnLength)
    {
        int32_t disp;
        std::memcpy(&disp, insn + dispOffset, sizeof(disp));
        return insn + insnLength + disp;
    }
} // namespace modloader::sigscan

char* findSignature(const char* pattern) { return modloader::sigscan::findUnique(pattern); }
