// SPDX-License-Identifier: MPL-2.0
// Copyright © 2023 Skyline Team and Contributors (https://github.com/skyline.emu/)

#include <android/sharedmem.h>
#include "KMemory.h"
#include "KProcess.h"

namespace skyline::kernel::type {
    KMemory::KMemory(const DeviceState &state, KType objectType, size_t size) : KObject(state, objectType), guest() {
        fileDescriptor = ASharedMemory_create(objectType == KType::KSharedMemory ? "HOS-KSharedMemory" : "HOS-KTransferMemory", size);
        if (fileDescriptor < 0) [[unlikely]]
            throw exception("Failed to create shared memory object: {}", fileDescriptor);

        u8 *hostPtr{static_cast<u8 *>(mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fileDescriptor, 0))};
        if (hostPtr == MAP_FAILED) [[unlikely]]
            throw exception("Failed to map shared memory object: {}", strerror(errno));

        host = span<u8>{hostPtr, size};
    }

    u8 *KMemory::Map(span<u8> map, memory::Permission permission) {
        if (!state.process->memory.AddressSpaceContains(map)) [[unlikely]]
            throw exception("(KMemory) Address space does not contain the memory object: 0x{:X} - 0x{:X}", map.data(), map.end().base());
        if (!util::IsPageAligned(map.data()) || !util::IsPageAligned(map.size())) [[unlikely]]
            throw exception("(KMemory) Address is not page aligned: 0x{:X} - 0x{:X}", map.data(), map.end().base());
        if (guest.valid()) [[unlikely]]
            throw exception("(KMemory) Memory object is already mapped");

        if (mmap(map.data(), map.size(), permission.Get() ? PROT_READ | PROT_WRITE : PROT_NONE, MAP_SHARED | (map.data() ? MAP_FIXED : 0), fileDescriptor, 0) == MAP_FAILED) [[unlikely]]
            throw exception("(KMemory) Failed to map memory object: {}", strerror(errno));

        guest = map;

        return guest.data();
    }

    void KMemory::Unmap(span<u8> map) {
        if (!state.process->memory.AddressSpaceContains(map)) [[unlikely]]
            throw exception("(KMemory) Address space does not contain the memory object: 0x{:X} - 0x{:X}", map.data(), map.end().base());
        if (!util::IsPageAligned(map.data()) || !util::IsPageAligned(map.size())) [[unlikely]]
            throw exception("(KMemory) Address is not page aligned: 0x{:X} - 0x{:X}", map.data(), map.end().base());
        if (guest.data() != map.data() && guest.size() != map.size()) [[unlikely]]
            throw exception("(KMemory) Unmapping partially not supported: Requested Unmap: 0x{:X} - 0x{:X} (0x{:X}), Current Mapping: 0x{:X} - 0x{:X} (0x{:X})", map.data(), map.end().base(), map.size(), guest.data(), guest.end().base(), guest.size());

        if (mmap(map.data(), map.size(), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0) == MAP_FAILED) [[unlikely]]
            throw exception("(KMemory) Failed to unmap memory object: {}", strerror(errno));
    }

    KMemory::~KMemory() {
        if (host.valid())
            munmap(host.data(), host.size());

        close(fileDescriptor);
    }
}