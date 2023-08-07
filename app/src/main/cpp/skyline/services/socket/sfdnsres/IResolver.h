// SPDX-License-Identifier: MPL-2.0
// Copyright © 2020 Skyline Team and Contributors (https://github.com/skyline-emu/)

#pragma once

#include <services/serviceman.h>

namespace skyline::service::socket {
    // https://github.com/yuzu-emu/yuzu/blob/master/src/core/hle/service/sockets/sfdnsres.cpp
    enum class NetDbError : i32 {
        Internal = -1,
        Success = 0,
        HostNotFound = 1,
        TryAgain = 2,
        NoRecovery = 3,
        NoData = 4,
    };

    enum class Domain : u8 {
        Unspecified,
        INET
    };

    enum class Type {
        Unspecified,
        STREAM,
        DGRAM,
        RAW,
        SEQPACKET
    };

    enum class Protocol : u8 {
        Unspecified,
        ICMP,
        TCP,
        UDP
    };

    struct SockAddrIn {
        Domain family;
        std::array<u8, 4> ip;
        u16 port;
    };

    struct AddrInfo {
        Domain family;
        Type socket_type;
        Protocol protocol;
        SockAddrIn address;
        std::optional<std::string> canon_name;
    };

    /**
     * @url https://switchbrew.org/wiki/Sockets_services#sfdnsres
     */
    class IResolver : public BaseService {
      private:
        static std::pair<u32, i32> GetAddrInfoRequestImpl(ipc::IpcRequest &request);
      public:
        IResolver(const DeviceState &state, ServiceManager &manager);

        Result SetDnsAddressesPrivateRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result GetDnsAddressPrivateRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result GetHostByNameRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result GetHostByAddrRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result GetHostStringErrorRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result GetGaiStringErrorRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result GetAddrInfoRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result GetNameInfoRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result GetCancelHandleRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result CancelRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result GetHostByNameRequestWithOptions(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result GetHostByAddrRequestWithOptions(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result GetAddrInfoRequestWithOptions(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result GetNameInfoRequestWithOptions(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result ResolverSetOptionRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        Result ResolverGetOptionRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response);

        SERVICE_DECL(
            SFUNC(0x0, IResolver, SetDnsAddressesPrivateRequest),
            SFUNC(0x1, IResolver, GetDnsAddressPrivateRequest),
            SFUNC(0x2, IResolver, GetHostByNameRequest),
            SFUNC(0x3, IResolver, GetHostByAddrRequest),
            SFUNC(0x4, IResolver, GetHostStringErrorRequest),
            SFUNC(0x5, IResolver, GetGaiStringErrorRequest),
            SFUNC(0x6, IResolver, GetAddrInfoRequest),
            SFUNC(0x7, IResolver, GetNameInfoRequest),
            SFUNC(0x8, IResolver, GetCancelHandleRequest),
            SFUNC(0x9, IResolver, CancelRequest),
            SFUNC(0xA, IResolver, GetHostByNameRequestWithOptions),
            SFUNC(0xB, IResolver, GetHostByAddrRequestWithOptions),
            SFUNC(0xC, IResolver, GetAddrInfoRequestWithOptions),
            SFUNC(0xD, IResolver, GetNameInfoRequestWithOptions),
            SFUNC(0xE, IResolver, ResolverSetOptionRequest),
            SFUNC(0xF, IResolver, ResolverGetOptionRequest)
        )
    };
}
