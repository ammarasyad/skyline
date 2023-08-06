#include "IClkrstManager.h"
#include "IClkrstSession.h"

namespace skyline::service::clkrst {
    IClkrstManager::IClkrstManager(const DeviceState &state, ServiceManager &manager) : BaseService(state, manager) {}

    Result IClkrstManager::OpenSession(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        manager.RegisterService(SRVREG(IClkrstSession), session, response);
        return {};
    }
}
