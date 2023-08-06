#pragma once

#include <services/serviceman.h>

namespace skyline::service::clkrst {
    class IClkrstManager : public BaseService {
      public:
        IClkrstManager(const DeviceState &state, ServiceManager &manager);

        Result OpenSession(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        SERVICE_DECL(
            SFUNC(0x0, IClkrstManager, OpenSession)
        )
    };
}