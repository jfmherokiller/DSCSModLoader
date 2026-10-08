#include "modloader/utils.h"

#include <Windows.h>

#include <sstream>

char* getBaseOffset()
{
    static char* offset = (char*)GetModuleHandle(NULL);
    return offset;
}

void patchBytes(const std::vector<uint8_t>& data, void* address)
{
    DWORD flag  = 0;
    size_t size = data.size();

    VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &flag);
    std::copy_n(data.data(), size, static_cast<uint8_t*>(address));
    VirtualProtect(address, size, flag, &flag);
    FlushInstructionCache(GetCurrentProcess(), address, size);
}

void patchBytes(const std::vector<uint8_t>& data, const uint64_t offset) { patchBytes(data, getBaseOffset() + offset); }

void redirectJump(const void* target, void* address)
{
    const std::vector<uint8_t> injectionData = {
        (uint8_t)0x48, (uint8_t)0xB8, ptr2bytes(target), // MOV RAX,target
        (uint8_t)0xFF, (uint8_t)0xE0,                    // JMP RAX
    };

    patchBytes(injectionData, address);
}

void redirectJump(const void* target, const uint64_t offset) { redirectJump(target, getBaseOffset() + offset); }

void redirectCall(const void* target, void* address)
{
    const std::vector<uint8_t> injectionData = {
        (uint8_t)0x48, (uint8_t)0xB8, ptr2bytes(target), // MOV RAX,target
        (uint8_t)0xFF, (uint8_t)0xD0,                    // CALL RAX
    };

    patchBytes(injectionData, address);
}

void redirectCall(const void* target, const uint64_t offset) { redirectCall(target, getBaseOffset() + offset); }

bool patchRel32(void* insn, int32_t dispOffset, int32_t insnLength, const void* target)
{
    const auto next  = reinterpret_cast<intptr_t>(insn) + insnLength;
    const auto delta = reinterpret_cast<intptr_t>(target) - next;
    if (delta < INT32_MIN || delta > INT32_MAX) return false;

    const auto rel = static_cast<int32_t>(delta);
    const std::vector<uint8_t> data(reinterpret_cast<const uint8_t*>(&rel), reinterpret_cast<const uint8_t*>(&rel) + 4);
    patchBytes(data, static_cast<char*>(insn) + dispOffset);
    return true;
}

const HexToStringResult parseByteArray(const std::string& str, std::vector<uint8_t>& vector)
{
    std::stringstream sstream(str);
    std::vector<uint8_t> local;

    while (!sstream.eof())
    {
        std::string val;
        sstream >> val;

        if (val.size() != 2) return HexToStringResult::WRONG_TOKEN_SIZE;

        std::size_t pos;
        local.push_back(std::stoi(val, &pos, 16));

        if (pos != val.size()) return HexToStringResult::INVALID_TOKEN;
    }

    vector.insert(vector.end(), local.begin(), local.end());
    return HexToStringResult::SUCCESS;
}
