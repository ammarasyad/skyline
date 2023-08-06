// SPDX-License-Identifier: MPL-2.0
// Copyright © 2020 Skyline Team and Contributors (https://github.com/skyline-emu/)

#include "IDisplayController.h"

namespace skyline::service::am {
    IDisplayController::IDisplayController(const DeviceState &state, ServiceManager &manager) : BaseService(state, manager) {}

    Result IDisplayController::TakeScreenShotOfOwnLayer(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        auto unknown{request.Pop<u32>()};
        auto unknown2{request.Pop<bool>()};

        Logger::Debug("TakeScreenShotOfOwnLayer: unknown: {}, unknown2: {}", unknown, unknown2);
        return {};
    }

    Result IDisplayController::ReleaseLastApplicationCaptureBuffer(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }

    Result IDisplayController::ReleaseCallerAppletCaptureBuffer(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }

    Result IDisplayController::AcquireLastApplicationCaptureBufferEx(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }

    Result IDisplayController::AcquireCallerAppletCaptureBufferEx(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }
}
