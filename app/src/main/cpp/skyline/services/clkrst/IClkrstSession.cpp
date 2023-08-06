#include "IClkrstSession.h"

namespace skyline::service::clkrst {
    IClkrstSession::IClkrstSession(const DeviceState &state, ServiceManager &manager) : BaseService(state, manager) {}
}
