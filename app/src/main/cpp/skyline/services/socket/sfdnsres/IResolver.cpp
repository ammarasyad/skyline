// SPDX-License-Identifier: MPL-2.0
// Copyright © 2020 Skyline Team and Contributors (https://github.com/skyline-emu/)

#include <netdb.h>
#include <sys/endian.h>
#include <linux/in.h>
#include <arpa/inet.h>
#include "IResolver.h"

namespace skyline::service::socket {
    static NetDbError AddrInfoErrorToNetDbError(i32 result) {
        switch (result) {
            case 0:
                return NetDbError::Success;
            case EAI_AGAIN:
                return NetDbError::TryAgain;
            case EAI_NODATA:
                return NetDbError::NoData;
            default:
                return NetDbError::HostNotFound;
        }
    }

    IResolver::IResolver(const DeviceState &state, ServiceManager &manager) : BaseService(state, manager) {}

    Result IResolver::SetDnsAddressesPrivateRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        response.Push<u32>(0x7FE03);
        return {};
    }

    Result IResolver::GetDnsAddressPrivateRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        response.Push<u32>(0x7FE03);
        return {};
    }

    Result IResolver::GetHostByNameRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }

    Result IResolver::GetHostByAddrRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }

    Result IResolver::GetHostStringErrorRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }

    Result IResolver::GetGaiStringErrorRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }

    Result IResolver::GetAddrInfoRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        auto [size, result]{GetAddrInfoRequestImpl(request)};
        response.Push<i32>(result);
        response.Push(AddrInfoErrorToNetDbError(result));
        response.Push<u32>(size);
        return {};
    }

    Result IResolver::GetNameInfoRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }

    Result IResolver::GetCancelHandleRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }

    Result IResolver::CancelRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }

    Result IResolver::GetHostByNameRequestWithOptions(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }

    Result IResolver::GetHostByAddrRequestWithOptions(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }

    Result IResolver::GetAddrInfoRequestWithOptions(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        auto [size, result]{GetAddrInfoRequestImpl(request)};
        response.Push<i32>(result);
        response.Push(AddrInfoErrorToNetDbError(result));
        response.Push<u32>(size);
        response.Push<u32>(0);
        return {};
    }

    Result IResolver::GetNameInfoRequestWithOptions(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }

    Result IResolver::ResolverSetOptionRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }

    Result IResolver::ResolverGetOptionRequest(type::KSession &session, ipc::IpcRequest &request, ipc::IpcResponse &response) {
        return {};
    }

    static std::vector<u8> SerializeAddrInfo(const addrinfo *addrinfo, i32 result_code, std::string_view host) {
        std::vector<u8> data;

        auto *current = addrinfo;
        while (current != nullptr) {
            struct SerializedResponseHeader {
                u32 magic;
                u32 flags;
                u32 family;
                u32 socket_type;
                u32 protocol;
                u32 address_length;
            };

            static_assert(sizeof(SerializedResponseHeader) == 0x18, "SerializedResponseHeader must be 0x18 bytes");

            constexpr auto header_size = sizeof(SerializedResponseHeader);
            const auto addr_size = current->ai_addr && current->ai_addrlen > 0 ? current->ai_addrlen : 4;
            const auto canonname_size = current->ai_canonname ? strlen(current->ai_canonname) + 1 : 1;

            const auto last_size = data.size();
            data.resize(last_size + header_size + addr_size + canonname_size);

            SerializedResponseHeader header{
                .magic = 0xBEEFCAFE,
                .flags = htonl(current->ai_flags),
                .family = htonl(current->ai_family),
                .socket_type = htonl(current->ai_socktype),
                .protocol = htonl(current->ai_protocol),
                .address_length = current->ai_addr ? htonl(current->ai_addrlen) : 0
            };

            auto *header_ptr{data.data() + last_size};
            memcpy(header_ptr, &header, header_size);

            if (header.address_length > 0) {
                switch (current->ai_family) {
                    case AF_INET: {
                        struct SockAddrIn {
                            u16 family;
                            u16 port;
                            u32 address;
                            u8 zero[8];
                        };

                        const auto addr = *reinterpret_cast<const sockaddr_in *>(current->ai_addr);
                        SockAddrIn serialized_addr{
                            .family = htons(addr.sin_family),
                            .port = htons(addr.sin_port),
                            .address = htonl(addr.sin_addr.s_addr),
                        };

                        memcpy(header_ptr + header_size, &serialized_addr, sizeof(SockAddrIn));

                        char addr_str_buf[64];
                        inet_ntop(AF_INET, &addr.sin_addr, addr_str_buf, std::size(addr_str_buf));
                        Logger::Info("Resolved '{}' to {}", host.data(), addr_str_buf);
                        break;
                    }
                    case AF_INET6: {
                        struct SockAddrIn6 {
                            u16 family;
                            u16 port;
                            u32 flowinfo;
                            u8 address[16];
                            u32 scope_id;
                        };

                        const auto addr = *reinterpret_cast<const sockaddr_in6 *>(current->ai_addr);
                        SockAddrIn6 serialized_addr{
                            .family = htons(addr.sin6_family),
                            .port = htons(addr.sin6_port),
                            .flowinfo = htonl(addr.sin6_flowinfo),
                            .scope_id = htonl(addr.sin6_scope_id),
                        };

                        memcpy(serialized_addr.address, &addr.sin6_addr, sizeof(SockAddrIn6::address));
                        memcpy(header_ptr + header_size, &serialized_addr, sizeof(SockAddrIn6));

                        char addr_str_buf[64];
                        inet_ntop(AF_INET6, &addr.sin6_addr, addr_str_buf, std::size(addr_str_buf));
                        Logger::Info("Resolved '{}' to {}", host.data(), addr_str_buf);
                        break;
                    }
                    default: {
                        memcpy(header_ptr + header_size, current->ai_addr, addr_size);
                        break;
                    }
                }
            } else {
                memset(header_ptr + header_size, 0, 4);
            }

            if (current->ai_canonname) {
                memcpy(header_ptr + addr_size, current->ai_canonname, canonname_size);
            } else {
                memset(header_ptr + header_size + addr_size, 0, 1);
            }

            current = current->ai_next;
        }

        // 4-byte sentinel value
        #pragma unroll
        for (size_t i = 0; i < 4; i++) {
            data.push_back(0);
        }

        return data;
    }

    std::pair<u32, i32> IResolver::GetAddrInfoRequestImpl(ipc::IpcRequest &request) {
        auto hostname{request.inputBuf.at(0).as_string(true)};
        auto service{request.inputBuf.at(1).as_string(true)};

        addrinfo *result;
        i32 resultCode = getaddrinfo(hostname.data(), service.data(), nullptr, &result);

        u32 size{0};
        if (!resultCode && result != nullptr) {
            const std::vector<u8> data = SerializeAddrInfo(result, resultCode, hostname);
            size = static_cast<u32>(data.size());
            request.outputBuf.at(0).copy_from(data);
            freeaddrinfo(result);
        }

        return {size, resultCode};
    }
}
