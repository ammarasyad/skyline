#include "ISaveDataInfoReader.h"

namespace skyline::service::fssrv {
    ISaveDataInfoReader::ISaveDataInfoReader(const DeviceState &state, ServiceManager &manager) : BaseService(state, manager) {}
}