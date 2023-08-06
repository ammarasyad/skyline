// SPDX-License-Identifier: MPL-2.0
// Copyright © 2020 Skyline Team and Contributors (https://github.com/skyline-emu/)

#pragma once

#include <services/serviceman.h>

namespace skyline::service::am {
    /**
     * @brief This is used to capture the contents of a display
     * @url https://switchbrew.org/wiki/Applet_Manager_services#IDisplayController
     */
    class IDisplayController : public BaseService {
      public:
        IDisplayController(const DeviceState &state, ServiceManager &manager);

        Result TakeScreenShotOfOwnLayer(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result ReleaseLastApplicationCaptureBuffer(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result ReleaseCallerAppletCaptureBuffer(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result AcquireLastApplicationCaptureBufferEx(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result AcquireCallerAppletCaptureBufferEx(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        SERVICE_DECL(
            SFUNC(0x8, IDisplayController, TakeScreenShotOfOwnLayer),
            SFUNC(0xA, IDisplayController, AcquireLastApplicationCaptureBufferEx),
            SFUNC(0xB, IDisplayController, ReleaseLastApplicationCaptureBuffer),
            SFUNC(0xF, IDisplayController, ReleaseCallerAppletCaptureBuffer),
            SFUNC(0x12, IDisplayController, AcquireCallerAppletCaptureBufferEx)
        )
    };
}
