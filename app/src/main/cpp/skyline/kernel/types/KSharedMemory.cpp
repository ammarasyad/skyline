// SPDX-License-Identifier: MPL-2.0
// Copyright © 2020 Skyline Team and Contributors (https://github.com/skyline-emu/)

#include "KSharedMemory.h"
#include "KProcess.h"

namespace skyline::kernel::type {
    KSharedMemory::KSharedMemory(const DeviceState &state, size_t size)
        : KMemory(state, KType::KSharedMemory, size) {}

    u8 *KSharedMemory::Map(span<u8> map, memory::Permission permission) {
        u8 *result{KMemory::Map(map, permission)};
        state.process->memory.MapSharedMemory(guest, permission);
        return result;
    }

    void KSharedMemory::Unmap(span<u8> map) {
        KMemory::Unmap(map);
        guest = span<u8>{};
        state.process->memory.UnmapMemory(guest);
    }

    KSharedMemory::~KSharedMemory() {
        if (state.process && guest.valid()) {
            if (mmap(guest.data(), guest.size(), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED, -1, 0) == MAP_FAILED) [[unlikely]]
                Logger::Warn("Failed to unmap shared memory: {}", strerror(errno));

            state.process->memory.UnmapMemory(guest);
        }
    }
}
