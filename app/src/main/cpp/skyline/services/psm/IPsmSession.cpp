#include "IPsmSession.h"

namespace skyline::service::psm {
    IPsmSession::IPsmSession(const DeviceState &state, ServiceManager &manager) : stateChangeEvent(std::make_shared<type::KEvent>(state, false)), BaseService(state, manager) {}

    Result IPsmSession::BindStateChangeEvent(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        auto handle{state.process->InsertItem(stateChangeEvent)};
        response.copyHandles.push_back(handle);
        return {};
    }

    Result IPsmSession::UnbindStateChangeEvent(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }

    Result IPsmSession::SetChargerTypeChangeEventEnabled(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }

    Result IPsmSession::SetPowerSupplyChangeEventEnabled(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }

    Result IPsmSession::SetBatteryVoltageStateChangeEventEnabled(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }
}