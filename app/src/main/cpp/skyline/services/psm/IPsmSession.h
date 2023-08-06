#pragma once

#include <services/serviceman.h>

namespace skyline::service::psm {
    class IPsmSession : public BaseService {
      private:
        std::shared_ptr<kernel::type::KEvent> stateChangeEvent;

      public:
        IPsmSession(const DeviceState &state, ServiceManager &manager);

        Result BindStateChangeEvent(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result UnbindStateChangeEvent(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result SetChargerTypeChangeEventEnabled(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result SetPowerSupplyChangeEventEnabled(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result SetBatteryVoltageStateChangeEventEnabled(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        SERVICE_DECL(
            SFUNC(0x0, IPsmSession, BindStateChangeEvent),
            SFUNC(0x1, IPsmSession, UnbindStateChangeEvent),
            SFUNC(0x2, IPsmSession, SetChargerTypeChangeEventEnabled),
            SFUNC(0x3, IPsmSession, SetPowerSupplyChangeEventEnabled),
            SFUNC(0x4, IPsmSession, SetBatteryVoltageStateChangeEventEnabled)
        )
    };
}