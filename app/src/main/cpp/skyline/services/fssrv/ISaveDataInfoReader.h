#pragma once

#include <services/serviceman.h>

namespace skyline::service::fssrv {
    class ISaveDataInfoReader : public BaseService {
      public:
        ISaveDataInfoReader(const DeviceState &state, ServiceManager &manager);
    };
}