#pragma once

#include <services/serviceman.h>

namespace skyline::service::psm {
    class IPsmServer : public BaseService {
      public:
        IPsmServer(const DeviceState &state, ServiceManager &manager);

        Result GetBatteryChargePercentage(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result GetChargerType(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result IsBatteryChargingEnabled(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result OpenSession(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result GetBatteryVoltageState(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        SERVICE_DECL(
            SFUNC(0x1, IPsmServer, GetBatteryChargePercentage),
            SFUNC(0x2, IPsmServer, GetChargerType),
            SFUNC(0x4, IPsmServer, IsBatteryChargingEnabled),
            SFUNC(0x7, IPsmServer, OpenSession),
            SFUNC(0xB, IPsmServer, GetBatteryVoltageState)
        )
    };
}