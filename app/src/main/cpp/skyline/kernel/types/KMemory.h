// SPDX-License-Identifier: MPL-2.0
// Copyright © 2020 Skyline Team and Contributors (https://github.com/skyline-emu/)

#pragma once

#include <kernel/memory.h>
#include "KObject.h"

namespace skyline::kernel::type {
    /**
     * @brief The base kernel memory object that other memory classes derieve from
     */
    class KMemory : public KObject {
      private:
        int fileDescriptor; //!< The file descriptor of the memory object

      public:
        KMemory(const DeviceState &state, KType objectType, size_t size);

        /**
         * @return A span representing the memory object on the guest
         */
        span <u8> guest;
        span <u8> host;

        virtual u8 *Map(span<u8> map, memory::Permission permission);

        virtual void Unmap(span<u8> map);

        virtual ~KMemory();
    };
}
