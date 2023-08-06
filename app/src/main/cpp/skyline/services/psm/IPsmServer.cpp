#include "IPsmServer.h"
#include "IPsmSession.h"
#include "jvm.h"

namespace skyline::service::psm {
    IPsmServer::IPsmServer(const DeviceState &state, ServiceManager &manager) : BaseService(state, manager) {}

    Result IPsmServer::GetBatteryChargePercentage(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        response.Push<u32>(static_cast<u32>(state.jvm->GetBatteryLevelPercentage()));
        return {};
    }

    Result IPsmServer::GetChargerType(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        response.Push<u32>(static_cast<u32>(state.jvm->GetChargingType()));
        return {};
    }

    Result IPsmServer::IsBatteryChargingEnabled(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        response.Push<bool>(static_cast<u32>(state.jvm->GetChargingType()) != 0);
        return {};
    }

    Result IPsmServer::OpenSession(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        manager.RegisterService(SRVREG(IPsmSession), session, response);
        return {};
    }

    Result IPsmServer::GetBatteryVoltageState(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        // This is unimportant
        response.Push<u32>(3);
        return {};
    }
}