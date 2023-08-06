#pragma once

#include <services/serviceman.h>

namespace skyline::service::clkrst {
    class IClkrstSession : public BaseService {
      public:
        IClkrstSession(const DeviceState &state, ServiceManager &manager);
    };
}