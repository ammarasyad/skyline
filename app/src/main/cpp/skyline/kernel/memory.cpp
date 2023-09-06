// SPDX-License-Identifier: MPL-2.0
// Copyright © 2020 Skyline Team and Contributors (https://github.com/skyline-emu/)

#include <asm-generic/unistd.h>
#include <fcntl.h>
#include "memory.h"
#include "types/KProcess.h"

namespace skyline::kernel {
    MemoryManager::MemoryManager(const DeviceState &state) noexcept : state(state), processHeapSize(), memoryRefs() {}

    MemoryManager::~MemoryManager() noexcept {
        if (base.valid() && !base.empty())
            munmap(reinterpret_cast<void *>(base.data()), base.size());
        if (addressSpaceType != memory::AddressSpaceType::AddressSpace39Bit && codeBase36Bit.valid() && !codeBase36Bit.empty())
            munmap(reinterpret_cast<void *>(codeBase36Bit.data()), codeBase36Bit.size());
    }

    constexpr size_t RegionAlignment{1ULL << 21}; //!< The minimum alignment of a HOS memory region
    constexpr size_t CodeRegionSize{4ULL * 1024 * 1024 * 1024}; //!< The assumed maximum size of the code region (4GiB)

    void MemoryManager::MapInternal(const std::pair<u8 *, ChunkDescriptor> &chunk) {
        auto firstChunkBase{chunks.lower_bound(chunk.first)};
        auto lastChunkBase{chunks.lower_bound(chunk.first + chunk.second.size)};

        if (chunk.first <= firstChunkBase->first)
            firstChunkBase--;

        if (chunk.first + chunk.second.size < lastChunkBase->first)
            lastChunkBase--;

        ChunkDescriptor firstChunk{firstChunkBase->second};
        ChunkDescriptor lastChunk{lastChunkBase->second};

        bool unmapped{chunk.second.state == memory::states::Unmapped};
        bool protection{false};

        if (firstChunkBase->first == lastChunkBase->first) {
            if (firstChunk.IsCompatible(chunk.second)) [[unlikely]] return;

            if ((firstChunk.state == memory::states::Unmapped) != unmapped)
                protection = true;

            firstChunk.size = static_cast<size_t>(chunk.first - firstChunkBase->first);
            chunks[firstChunkBase->first] = firstChunk;

            lastChunk.size = static_cast<size_t>(lastChunkBase->first + lastChunk.size - (chunk.first + chunk.second.size));
            chunks.insert({chunk.first + chunk.second.size, lastChunk});

            chunks.insert(chunk);
        } else {
            if ((firstChunkBase->first + firstChunk.size) != lastChunkBase->first) {
                auto temp{std::next(firstChunkBase)};

                while (temp->first != lastChunkBase->first) {
                    if ((temp->second.state != memory::states::Unmapped) != unmapped) {
                        protection = true;
                        break;
                    }

                    temp++;
                }

                chunks.erase(std::next(firstChunkBase), lastChunkBase);
            }

            bool shouldInsert {true};

            if (firstChunk.IsCompatible(chunk.second)) {
                firstChunk.size = static_cast<size_t>(chunk.first + chunk.second.size - firstChunkBase->first);
                chunks[firstChunkBase->first] = firstChunk;
                shouldInsert = false;
            } else if ((firstChunkBase->first + firstChunk.size) != chunk.first) {
                firstChunk.size = static_cast<size_t>(chunk.first - firstChunkBase->first);
                chunks[firstChunkBase->first] = firstChunk;

                if ((firstChunk.state == memory::states::Unmapped) != unmapped)
                    protection = true;
            }

            if (lastChunk.IsCompatible(chunk.second)) {
                u8 *oldBase{lastChunkBase->first};
                chunks.erase(lastChunkBase);

                if (shouldInsert) {
                    shouldInsert = false;
                    lastChunk.size = static_cast<size_t>(oldBase + lastChunk.size - chunk.first);
                    chunks[chunk.first] = lastChunk;
                } else {
                    firstChunk.size = static_cast<size_t>(oldBase + lastChunk.size - firstChunkBase->first);
                    chunks[firstChunkBase->first] = firstChunk;
                }
            } else if (lastChunkBase->first != (chunk.first + chunk.second.size)) {
                lastChunk.size = static_cast<size_t>(lastChunkBase->first + lastChunk.size - (chunk.first + chunk.second.size));

                chunks.erase(lastChunkBase);
                chunks[chunk.first + chunk.second.size] = lastChunk;

                if ((lastChunk.state == memory::states::Unmapped) != unmapped)
                    protection = true;
            }

            if (shouldInsert)
                chunks.insert(chunk);
        }

        if (protection)
            if (mprotect(chunk.first, chunk.second.size, !unmapped ? PROT_READ | PROT_WRITE | PROT_EXEC : PROT_NONE)) [[unlikely]]
                Logger::Warn("Failed to set memory protection at 0x{:X} ({} bytes): {}", chunk.first, chunk.second.size, strerror(errno));
    }

    void MemoryManager::ForeachChunk(span<u8> memory, auto editCallback) {
        auto chunkBase{chunks.lower_bound(memory.data())};
        if (memory.data() < chunkBase->first)
            chunkBase--;

        size_t size{memory.size()};

        if (chunkBase->first < memory.data()) [[unlikely]] {
            size_t chunkSize{std::min<size_t>(chunkBase->second.size - static_cast<size_t>(memory.data() - chunkBase->first), memory.size())};

            std::pair<u8 *, ChunkDescriptor> temp{memory.data(), chunkBase->second};
            temp.second.size = chunkSize;
            editCallback(temp);

            chunkBase++;
            size -= chunkSize;
        }

        while (size) {
            std::pair<u8 *, ChunkDescriptor> temp(*chunkBase);

            if (size >= chunkBase->second.size) [[likely]] {
                editCallback(temp);
                size -= chunkBase->second.size;
                chunkBase++;
            } else {
                temp.second.size = size;
                editCallback(temp);
                break;
            }
        }
    }

    static span<u8> AllocateMappedRange(size_t minSize, size_t align, size_t minAddress, size_t maxAddress, bool findLargest) {
        span<u8> region{};
        size_t size{minSize};

        std::ifstream mapsFile("/proc/self/maps");
        std::string maps((std::istreambuf_iterator<char>(mapsFile)), std::istreambuf_iterator<char>());
        size_t line{}, start{minAddress}, alignedStart{minAddress};
        do {
            auto end{util::HexStringToInt<u64>(std::string_view(maps.data() + line, sizeof(u64) * 2))};
            if (end < start)
                continue;
            if (end - start > size + (alignedStart - start)) { // We don't want to overflow if alignedStart > start
                if (findLargest)
                    size = end - start;

                region = span<u8>{reinterpret_cast<u8 *>(alignedStart), size};

                if (!findLargest)
                    break;
            }

            start = util::HexStringToInt<u64>(std::string_view(maps.data() + maps.find_first_of('-', line) + 1, sizeof(u64) * 2));
            alignedStart = util::AlignUp(start, align);
            if (alignedStart + size > maxAddress) // We don't want to map past the end of the address space
                break;
        } while ((line = maps.find_first_of('\n', line)) != std::string::npos && line++);

        if (!region.valid()) [[unlikely]]
            throw exception("Allocation failed");

        auto result{mmap(reinterpret_cast<void *>(region.data()), size, PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_SHARED, -1, 0)};
        if (result == MAP_FAILED) [[unlikely]]
            throw exception("Failed to mmap guest address space: {}", strerror(errno));

        return region;
    }

    void MemoryManager::InitializeVmm(memory::AddressSpaceType type) {
        addressSpaceType = type;

        size_t baseSize{};
        switch (type) {
            case memory::AddressSpaceType::AddressSpace32Bit:
            case memory::AddressSpaceType::AddressSpace32BitNoReserved:
                throw exception("32-bit address spaces are not supported");

            case memory::AddressSpaceType::AddressSpace36Bit: {
                addressSpace = span<u8>{reinterpret_cast<u8 *>(0), (1ULL << 36)};
                baseSize = 0x180000000 + 0x180000000;
                break;
            }

            case memory::AddressSpaceType::AddressSpace39Bit: {
                addressSpace = span<u8>{reinterpret_cast<u8 *>(0), 1ULL << 39};
                baseSize = CodeRegionSize + 0x1000000000 + 0x180000000 + 0x80000000 + 0x1000000000;
                break;
            }

            default:
                throw exception("VMM initialization with unknown address space");
        }

        // Qualcomm KGSL (Kernel Graphic Support Layer/Kernel GPU driver) maps below 35-bits, reserving it causes KGSL to go OOM
        static constexpr size_t KgslReservedRegionSize{1ULL << 35};

        base = AllocateMappedRange(baseSize, RegionAlignment, KgslReservedRegionSize, addressSpace.size(), false);

        if (type != memory::AddressSpaceType::AddressSpace36Bit) {
            code = base;
        } else {
            code = codeBase36Bit = AllocateMappedRange(0x78000000, RegionAlignment, 0x08000000, KgslReservedRegionSize, false);

            if ((reinterpret_cast<u64>(base.data()) + baseSize) > (1ULL << 36)) {
                Logger::Warn("Base address space is above 36-bits, resizing code region to 39 bits");
                addressSpace = span<u8>{reinterpret_cast<u8 *>(0), 1ULL << 39};
            }
        }

        chunks = {{addressSpace.data(), {
            .size = addressSpace.size(),
            .state = memory::states::Unmapped
        }}, {reinterpret_cast<u8 *>(UINT64_MAX), {
            .state = memory::states::Reserved
        }}};
    }

    void MemoryManager::InitializeRegions(span<u8> codeRegion) {
        if (!util::IsAligned(codeRegion.data(), RegionAlignment)) [[unlikely]]
            throw exception("Non-aligned code region was used to initialize regions: 0x{:X} - 0x{:X}", codeRegion.data(), codeRegion.end().base());

        switch (addressSpaceType) {
            case memory::AddressSpaceType::AddressSpace36Bit: {
                if (codeBase36Bit.data() != reinterpret_cast<u8 *>(0x08000000))
                    MapInternal(std::pair<u8 *, ChunkDescriptor>(reinterpret_cast<u8 *>(0x08000000), {
                        .size = reinterpret_cast<size_t>(codeBase36Bit.data() - 0x08000000),
                        .state = memory::states::Heap
                    }));

                // Place code, stack and TLS/IO in the lower 36-bits of the host AS and heap past that
                code = span<u8>{codeBase36Bit.data(), codeBase36Bit.data() + 0x70000000};
                stack = span<u8>{codeBase36Bit.data(), codeBase36Bit.data() + 0x78000000};
                tlsIo = stack; //!< TLS/IO is shared with Stack on 36-bit
                alias = span<u8>{base.data(), 0x180000000};
                heap = span<u8>{alias.end().base(), 0x180000000};
                break;
            }

            case memory::AddressSpaceType::AddressSpace39Bit: {
                code = span<u8>{base.data(), util::AlignUp(codeRegion.size(), RegionAlignment)};
                alias = span<u8>{code.end().base(), 0x1000000000};
                heap = span<u8>{alias.end().base(), 0x180000000};
                stack = span<u8>{heap.end().base(), 0x80000000};
                tlsIo = span<u8>{stack.end().base(), 0x1000000000};

                u64 size{code.size() + alias.size() + stack.size() + heap.size() + tlsIo.size()};

                if (size > base.size()) [[unlikely]]
                    throw exception("Guest VMM size has exceeded host carveout size: 0x{:X}/0x{:X} (Code: 0x{:X}/0x{:X})", size, base.size(), code.size(), CodeRegionSize);

                if (size != base.size()) [[likely]]
                    munmap(base.end().base(), size - base.size());
                break;
            }

            default:
                throw exception("Regions initialized without VMM initialization");
        }

        if (codeRegion.size() > code.size()) [[unlikely]]
            throw exception("Code region ({}) is smaller than mapped code size ({})", code.size(), codeRegion.size());

        Logger::Debug("Region Map:\nVMM Base: 0x{:X}\nCode Region: 0x{:X} - 0x{:X} (Size: 0x{:X})\nAlias Region: 0x{:X} - 0x{:X} (Size: 0x{:X})\nHeap Region: 0x{:X} - 0x{:X} (Size: 0x{:X})\nStack Region: 0x{:X} - 0x{:X} (Size: 0x{:X})\nTLS/IO Region: 0x{:X} - 0x{:X} (Size: 0x{:X})", base.data(), code.data(), code.end().base(), code.size(), alias.data(), alias.end().base(), alias.size(), heap.data(), heap.end().base(), heap.size(), stack.data(), stack.end().base(), stack.size(), tlsIo.data(), tlsIo.end().base(), tlsIo.size());
    }

    span<u8> MemoryManager::CreateMirror(span<u8> mapping) {
        if (!base.contains(mapping)) [[unlikely]]
            throw exception("Mapping is outside of VMM base: 0x{:X} - 0x{:X}", mapping.data(), mapping.end().base());

        auto offset{static_cast<size_t>(mapping.data() - base.data())};
        if (!util::IsPageAligned(offset) || !util::IsPageAligned(mapping.size())) [[unlikely]]
            throw exception("Mapping is not aligned to a page: 0x{:X}-0x{:X} (0x{:X})", mapping.data(), mapping.end().base(), offset);

        auto mirror{mremap(mapping.data(), 0, mapping.size(), MREMAP_MAYMOVE)};
        if (mirror == MAP_FAILED) [[unlikely]]
            throw exception("Failed to create mirror mapping at 0x{:X}-0x{:X} (0x{:X}): {}", mapping.data(), mapping.end().base(), offset, strerror(errno));

        mprotect(mirror, mapping.size(), PROT_READ | PROT_WRITE);

        return span<u8>{reinterpret_cast<u8 *>(mirror), mapping.size()};
    }

    span<u8> MemoryManager::CreateMirrors(const std::vector<span<u8>> &regions) {
        size_t totalSize{};
        for (const auto &region : regions)
            totalSize += region.size();

        auto mirrorBase{mmap(nullptr, totalSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)}; // Reserve address space for all mirrors
        if (mirrorBase == MAP_FAILED) [[unlikely]]
            throw exception("Failed to create mirror base: {} (0x{:X} bytes)", strerror(errno), totalSize);

        size_t mirrorOffset{};
        for (const auto &region : regions) {
            if (!base.contains(region)) [[unlikely]]
                throw exception("Mapping is outside of VMM base: 0x{:X} - 0x{:X}", region.data(), region.end().base());

            auto offset{static_cast<size_t>(region.data() - base.data())};
            if (!util::IsPageAligned(offset) || !util::IsPageAligned(region.size())) [[unlikely]]
                throw exception("Mapping is not aligned to a page: 0x{:X}-0x{:X} (0x{:X})", region.data(), region.end().base(), offset);

            auto mirror{mremap(region.data(), 0, region.size(), MREMAP_FIXED | MREMAP_MAYMOVE, reinterpret_cast<u8 *>(mirrorBase) + mirrorOffset)};
            if (mirror == MAP_FAILED) [[unlikely]]
                throw exception("Failed to create mirror mapping at 0x{:X}-0x{:X} (0x{:X}): {}", region.data(), region.end().base(), offset, strerror(errno));

            mprotect(mirror, region.size(), PROT_READ | PROT_WRITE);

            mirrorOffset += region.size();
        }

        if (mirrorOffset != totalSize) [[unlikely]]
            throw exception("Mirror size mismatch: 0x{:X} != 0x{:X}", mirrorOffset, totalSize);

        return span<u8>{reinterpret_cast<u8 *>(mirrorBase), totalSize};
    }

    void MemoryManager::SetRegionBorrowed(span<u8> memory, bool value) {
        std::unique_lock lock(mutex);

        ForeachChunk(memory, [&](auto &chunk) __attribute__((always_inline)) {
            chunk.second.attributes.isBorrowed = value;
            MapInternal(chunk);
        });
    }

    void MemoryManager::SetRegionCPUCaching(span<u8> memory, bool value) {
        std::unique_lock lock(mutex);

        ForeachChunk(memory, [&](auto &chunk) __attribute__((always_inline)) {
            chunk.second.attributes.isUncached = value;
            MapInternal(chunk);
        });
    }

    void MemoryManager::SetRegionPermission(span<u8> memory, memory::Permission permission) {
        std::unique_lock lock(mutex);

        ForeachChunk(memory, [&](auto &chunk) __attribute__((always_inline)) {
            chunk.second.permission = permission;
            MapInternal(chunk);
        });
    }

    __attribute__((always_inline)) void MemoryManager::FreeMemory(span<u8> memory) {
        u8 *alignedStart{util::AlignUp(memory.data(), constant::PageSize)};
        u8 *alignedEnd{util::AlignDown(memory.end().base(), constant::PageSize)};

        if (alignedStart < alignedEnd) [[likely]]
            if (madvise(alignedStart, static_cast<size_t>(alignedEnd - alignedStart), MADV_REMOVE) == -1) [[unlikely]]
                Logger::Error("Failed to free memory: {}", strerror(errno));
    }

    std::optional<std::pair<u8 *, ChunkDescriptor>> MemoryManager::Get(u8 *addr) {
        std::shared_lock lock(mutex);

        if (!addressSpace.contains(addr)) [[unlikely]]
            return std::nullopt;

        auto chunk{chunks.lower_bound(addr)};
        if (addr < chunk->first)
            chunk--;

        return std::make_optional(*chunk);
    }

    __attribute__((always_inline)) void MemoryManager::MapCodeMemory(span<u8> memory, memory::Permission permission) {
        std::unique_lock lock(mutex);

        MapInternal(std::pair<u8 *, ChunkDescriptor>{
            memory.data(),
            ChunkDescriptor{
                .size = memory.size(),
                .state = memory::states::Code,
                .permission = permission,
            }
        });
    }

    __attribute__((always_inline)) void MemoryManager::MapMutableCodeMemory(span<u8> memory) {
        std::unique_lock lock(mutex);

        MapInternal(std::pair<u8 *, ChunkDescriptor>{
            memory.data(),
            ChunkDescriptor{
                .size = memory.size(),
                .state = memory::states::CodeData,
                .permission = {true, true, false},
            }
        });
    }

    __attribute__((always_inline)) void MemoryManager::MapStackMemory(span<u8> memory) {
        std::unique_lock lock(mutex);

        MapInternal(std::pair<u8 *, ChunkDescriptor>{
            memory.data(),
            ChunkDescriptor{
                .size = memory.size(),
                .state = memory::states::Stack,
                .permission = {true, true, false},
                .isSrcMergeAllowed = false
            }
        });
    }

    __attribute__((always_inline)) void MemoryManager::MapHeapMemory(span<u8> memory) {
        std::unique_lock lock(mutex);

        MapInternal(std::pair<u8 *, ChunkDescriptor>{
            memory.data(),
            ChunkDescriptor{
                .size = memory.size(),
                .state = memory::states::Heap,
                .permission = {true, true, false},
            }
        });
    }

    __attribute__((always_inline)) void MemoryManager::MapSharedMemory(span<u8> memory, memory::Permission permission) {
        std::unique_lock lock(mutex);

        MapInternal(std::pair<u8 *, ChunkDescriptor>{
            memory.data(),
            ChunkDescriptor{
                .size = memory.size(),
                .state = memory::states::SharedMemory,
                .permission = permission,
                .isSrcMergeAllowed = false
            }
        });
    }

    __attribute__((always_inline)) void MemoryManager::MapTransferMemory(span<u8> memory, memory::Permission permission) {
        std::unique_lock lock(mutex);

        MapInternal(std::pair<u8 *, ChunkDescriptor>{
            memory.data(),
            ChunkDescriptor{
                .size = memory.size(),
                .state = permission.raw ? memory::states::SharedTransfered : memory::states::Transfered,
                .permission = permission,
                .isSrcMergeAllowed = false
            }
        });
    }

    __attribute__((always_inline)) void MemoryManager::MapThreadLocalMemory(span<u8> memory) {
        std::unique_lock lock(mutex);

        MapInternal(std::pair<u8 *, ChunkDescriptor>{
            memory.data(),
            ChunkDescriptor{
                .size = memory.size(),
                .state = memory::states::ThreadLocal,
                .permission = {true, true, false},
            }
        });
    }

    __attribute__((always_inline)) void MemoryManager::Reserve(span<u8> memory) {
        std::unique_lock lock(mutex);

        MapInternal(std::pair<u8 *, ChunkDescriptor>{
            memory.data(),
            ChunkDescriptor{
                .size = memory.size(),
                .state = memory::states::Reserved,
                .permission = {false, false, false},
            }
        });
    }

    __attribute__((always_inline)) void MemoryManager::UnmapMemory(span<u8> memory) {
        std::unique_lock lock(mutex);

        ForeachChunk(memory, [&](auto &chunk) {
            if (chunk.second.state != memory::states::Unmapped)
                FreeMemory(span<u8>(chunk.first, chunk.second.size));
        });

        MapInternal(std::pair<u8 *, ChunkDescriptor>(
            memory.data(),{
                .size = memory.size(),
                .permission = {false, false, false},
                .state = memory::states::Unmapped
            }));
    }

    void MemoryManager::SvcMapMemory(span<u8> src, span<u8> dst) {
        MapStackMemory(dst);

        std::memcpy(dst.data(), src.data(), src.size());

        ForeachChunk(src, [&](auto &desc) __attribute__((always_inline)) {
            desc.second.permission = {false, false, false};
            desc.second.attributes.isBorrowed = true;
            MapInternal(desc);
        });
    }

    void MemoryManager::SvcUnmapMemory(span<u8> src, span<u8> dst) {
        std::unique_lock lock(mutex);

        auto dstChunk = chunks.lower_bound(dst.data());
        if (dst.data() < dstChunk->first)
            dstChunk--;
        while (dstChunk->second.state.value == memory::states::Unmapped)
            dstChunk++;

        if ((dst.data() + dst.size()) > dstChunk->first) [[likely]] {
            ForeachChunk(span<u8>{src.data() + (dstChunk->first - dst.data()), dstChunk->second.size}, [&](auto &desc) __attribute__((always_inline)) {
                desc.second.permission = dstChunk->second.permission;
                desc.second.attributes.isBorrowed = false;
                MapInternal(desc);
            });

            std::memcpy(src.data() + (dstChunk->first - dst.data()), dstChunk->first, dstChunk->second.size);
        }
    }

    void MemoryManager::AddReference(std::shared_ptr<type::KMemory> ptr) {
        memoryRefs.push_back(std::move(ptr));
    }

    void MemoryManager::RemoveReference(const std::shared_ptr<type::KMemory>& ptr) {
//        auto i = std::find(memoryRefs.begin(), memoryRefs.end(), ptr);
//
//        if (*i == ptr) [[likely]]
//            memoryRefs.erase(i);
        memoryRefs.erase(std::remove(memoryRefs.begin(), memoryRefs.end(), ptr), memoryRefs.end());
    }

    size_t MemoryManager::GetUserMemoryUsage() {
        std::shared_lock lock(mutex);
        size_t size{};

        auto current = chunks.lower_bound(heap.data());

        while (current->first < heap.end().base()) {
            if (current->second.state == memory::states::Heap)
                size += current->second.size;
            current++;
        }
        return size + code.size() + state.process->mainThreadStack.size();
    }

    size_t MemoryManager::GetSystemResourceUsage() {
        std::shared_lock lock(mutex);
        constexpr size_t KMemoryBlockSize{0x40};
        return std::min(static_cast<size_t>(state.process->npdm.meta.systemResourceSize), util::AlignUp(chunks.size() * KMemoryBlockSize, constant::PageSize));
    }
}