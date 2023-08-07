// SPDX-License-Identifier: MPL-2.0
// Copyright © 2023 Skyline Team and Contributors (https://github.com/skyline-emu/)

#include "KTransferMemory.h"
#include "KProcess.h"

namespace skyline::kernel::type {
    KTransferMemory::KTransferMemory(const DeviceState &state, size_t size)
        : KMemory(state, KType::KTransferMemory, size) {}

    u8 *KTransferMemory::Map(span<u8> map, memory::Permission permission) {
        std::memcpy(host.data(), map.data(), map.size());
        u8 *result{KMemory::Map(map, permission)};

        auto old{state.process->memory.Get(map.data()).value()};
        chunkDescriptor = old.second;

        if (chunkDescriptor.state.transferMemoryAllowed) [[likely]] {
            state.process->memory.MapTransferMemory(guest, permission);
            state.process->memory.SetRegionBorrowed(guest, true);
            return result;
        }

        Logger::Warn("Attempted to map transfer memory that is not allowed to be mapped: 0x{:X} (0x{:X} bytes)", map.data(), map.size());
        return nullptr;
    }

    void KTransferMemory::Unmap(span<u8> map) {
        KMemory::Unmap(map);
        guest = span<u8>{};

        switch (chunkDescriptor.state.type) {
            case memory::MemoryType::CodeData:
                state.process->memory.MapMutableCodeMemory(map);
                break;
            case memory::MemoryType::Heap:
                state.process->memory.MapHeapMemory(map);
                break;
            default:
                Logger::Warn("Attempted to unmap transfer memory with incompatible state: 0x{:X}", chunkDescriptor.state.value);
        }

        std::memcpy(map.data(), host.data(), map.size());
    }

    KTransferMemory::~KTransferMemory() {
        if (state.process && guest.valid()) {
            if (mmap(guest.data(), guest.size(), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED | MAP_POPULATE, -1, 0) == MAP_FAILED) [[unlikely]]
                Logger::Warn("Failed to unmap transfer memory: {}", strerror(errno));

            switch (chunkDescriptor.state.type) {
                case memory::MemoryType::CodeData:
                    state.process->memory.MapMutableCodeMemory(guest);
                    break;
                case memory::MemoryType::Heap:
                    state.process->memory.MapHeapMemory(guest);
                    break;
                default:
                    Logger::Warn("Attempted to unmap transfer memory with incompatible state: 0x{:X}", chunkDescriptor.state.value);
            }

            std::memcpy(guest.data(), host.data(), guest.size());
        }
    }
}
