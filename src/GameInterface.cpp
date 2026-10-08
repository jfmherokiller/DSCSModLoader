#include "dscs/GameInterface.h"

#include "dscs/Savegame.h"
#include "dscs/Symbols.h"
#include "modloader/utils.h"

namespace dscs
{
    std::map<int32_t, SeenData*>* getSeenData()
    {
        using Func   = std::map<int32_t, SeenData*>* (*)();
        const Func f = symbols::as<Func>(symbols::Sym::GetSeenData);
        return f();
    }

    GameContext* getGameContext()
    {
        using Func   = GameContext* (*)();
        const Func f = symbols::as<Func>(symbols::Sym::GetGameContext);
        return f();
    }

    AppContext* getAppContext() { return symbols::as<AppContext*>(symbols::Sym::AppContext); }

    ResourceManagerContext* getResourceManagerContext()
    {
        return symbols::as<ResourceManagerContext*>(symbols::Sym::ResourceManagerContext);
    }

    DigisterMap* getDigisterMap()
    {
        using Func   = DigisterMap* (*)();
        const Func f = symbols::as<Func>(symbols::Sym::GetDigisterMap);
        return f();
    }

    SoundStruct* getSoundStruct()
    {
        using Func   = SoundStruct* (*)();
        const Func f = symbols::as<Func>(symbols::Sym::GetSoundStruct);
        return f();
    }

    ScanData* setScanData(DigimonContext* context, int32_t digimonId, uint16_t value)
    {
        using Func   = ScanData* (*)(DigimonContext*, int32_t, uint16_t);
        const Func f = symbols::as<Func>(symbols::Sym::SetScanData);
        return f(context, digimonId, value);
    }

    float getTimeDelta(double* timer)
    {
        using Func   = float (*)(double*);
        const Func f = symbols::as<Func>(symbols::Sym::GetTimeDelta);
        return f(timer);
    }

    bool useTargetDelta()
    {
        using Func   = bool (*)();
        const Func f = symbols::as<Func>(symbols::Sym::UseTargetDelta);
        return f();
    }

    int32_t getTargetFPS()
    {
        using Func   = int32_t (*)();
        const Func f = symbols::as<Func>(symbols::Sym::GetTargetFPS);
        return f();
    }

    GameSaveData* getGameSaveData() { return *symbols::as<GameSaveData**>(symbols::Sym::GameSaveData); }

    int32_t getSaveDirPath(char* buffer)
    {
        using Func   = int32_t (*)(char*);
        const Func f = symbols::as<Func>(symbols::Sym::GetSaveDirPath);
        return f(buffer);
    }

    void createSaveDir()
    {
        using Func   = void (*)();
        const Func f = symbols::as<Func>(symbols::Sym::CreateSaveDir);
        return f();
    }

    void encryptSaveFile(void* buffer, std::size_t size, uint64_t key)
    {
        using Func   = void (*)(void*, std::size_t, uint64_t);
        const Func f = symbols::as<Func>(symbols::Sym::EncryptSaveFile);
        return f(buffer, size, key);
    }

    void decryptSaveFile(void* buffer, std::size_t size, uint64_t key)
    {
        using Func   = void (*)(void*, std::size_t, uint64_t);
        const Func f = symbols::as<Func>(symbols::Sym::DecryptSaveFile);
        return f(buffer, size, key);
    }

    void endThread(int32_t returnValue)
    {
        using Func   = void (*)(int32_t);
        const Func f = symbols::as<Func>(symbols::Sym::EndThread);
        return f(returnValue);
    }

    char* getResourceDir()
    {
        using Func   = char* (*)(void);
        const Func f = symbols::as<Func>(symbols::Sym::GetResourceDirCStr);
        return f();
    }

    std::string getResourceDir(std::string* str)
    {
        using Func   = std::string (*)(std::string*);
        const Func f = symbols::as<Func>(symbols::Sym::GetResourceDirString);
        return f(str);
    }

    void addArchiveOverride(bool isPacked, const char* name) {
        auto manager = getResourceManagerContext()->manager;
        
        using Func   = void(*)(ResourceManager*, bool, const char*);
        const Func f = symbols::as<Func>(symbols::Sym::AddArchiveOverride);

        f(manager, isPacked, name);
    }

    void* wglGetProcAddress(const char* name)
    {
        using Func   = void* (*)(const char*);
        const Func f = *symbols::as<Func*>(symbols::Sym::IAT_wglGetProcAddress);

        return f(name);
    }

    FarmSaveEntry& FarmSaveEntry::operator=(const PartyEntry& entry)
    {
        this->isFilled   = entry.isFilled;
        this->field4_0x4 = entry.field4_0x4;
        this->field5_0x8 = entry.field5_0x8;
        this->field6_0xc = entry.field6_0xc;
        this->digimonPtr = *entry.digimonPtr;
        return *this;
    }

    FarmSaveEntry& FarmSaveEntry::operator=(const PartyEntry* entry)
    {
        this->isFilled   = entry->isFilled;
        this->field4_0x4 = entry->field4_0x4;
        this->field5_0x8 = entry->field5_0x8;
        this->field6_0xc = entry->field6_0xc;
        this->digimonPtr = *entry->digimonPtr;
        return *this;
    }

    BankSaveEntry& BankSaveEntry::operator=(const PartyEntry& entry)
    {
        this->isFilled   = entry.isFilled;
        this->field4_0x4 = entry.field4_0x4;
        this->field5_0x8 = entry.field5_0x8;
        this->digimonPtr = *entry.digimonPtr;
        return *this;
    }

    BankSaveEntry& BankSaveEntry::operator=(const PartyEntry* entry)
    {
        this->isFilled   = entry->isFilled;
        this->field4_0x4 = entry->field4_0x4;
        this->field5_0x8 = entry->field5_0x8;
        this->digimonPtr = *entry->digimonPtr;
        return *this;
    }

    PartyEntry& PartyEntry::operator=(const BankSaveEntry& entry)
    {
        this->isFilled    = entry.isFilled;
        this->field4_0x4  = entry.field4_0x4;
        this->field5_0x8  = entry.field5_0x8;
        *this->digimonPtr = entry.digimonPtr;
        return *this;
    }

    PartyEntry& PartyEntry::operator=(const BankSaveEntry* entry)
    {
        this->isFilled    = entry->isFilled;
        this->field4_0x4  = entry->field4_0x4;
        this->field5_0x8  = entry->field5_0x8;
        *this->digimonPtr = entry->digimonPtr;
        return *this;
    }

    PartyEntry& PartyEntry::operator=(const FarmSaveEntry& entry)
    {
        this->isFilled    = entry.isFilled;
        this->field4_0x4  = entry.field4_0x4;
        this->field5_0x8  = entry.field5_0x8;
        this->field6_0xc  = entry.field6_0xc;
        *this->digimonPtr = entry.digimonPtr;
        return *this;
    }

    PartyEntry& PartyEntry::operator=(const FarmSaveEntry* entry)
    {
        this->isFilled    = entry->isFilled;
        this->field4_0x4  = entry->field4_0x4;
        this->field5_0x8  = entry->field5_0x8;
        this->field6_0xc  = entry->field6_0xc;
        *this->digimonPtr = entry->digimonPtr;
        return *this;
    }
} // namespace dscs

namespace mediavision
{
    namespace symbols = dscs::symbols;

    namespace vfs
    {
        void deleteFile(const char* path)
        {
            using Func   = void (*)(const char*);
            const Func f = symbols::as<Func>(symbols::Sym::VfsDeleteFile);
            return f(path);
        }

        void createFile(const char* path)
        {
            using Func   = void (*)(const char*);
            const Func f = symbols::as<Func>(symbols::Sym::VfsCreateFile);
            return f(path);
        }

        uint64_t writeFile(const char* path, void* buffer, int32_t size)
        {
            using Func   = uint64_t (*)(const char*, void*, int32_t);
            const Func f = symbols::as<Func>(symbols::Sym::VfsWriteFile);
            return f(path, buffer, size);
        }

        bool readFile(const char* path, ReadHandle* buffer)
        {
            using Func   = bool (*)(const char*, ReadHandle*);
            const Func f = symbols::as<Func>(symbols::Sym::VfsReadFile);
            return f(path, buffer);
        }
    } // namespace vfs
} // namespace mediavision