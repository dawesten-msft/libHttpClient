// Copyright (c) Microsoft Corporation
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "pch.h"
#include "utils_win.h"
#include "uri.h"

#include <httpClient/trace.h>
#if !HC_XDK_API && !HC_UWP_API
#include <winhttp.h>
#include <VersionHelpers.h>
#include "../../HTTP/WinHttp/winhttp_http_provider.h"
#endif

http_internal_string utf8_from_utf16(const http_internal_wstring& utf16)
{
    return utf8_from_utf16(utf16.data(), utf16.size());
}

http_internal_wstring utf16_from_utf8(const http_internal_string& utf8)
{
    return utf16_from_utf8(utf8.data(), utf8.size());
}

http_internal_string utf8_from_utf16(_In_z_ PCWSTR utf16)
{
    return utf8_from_utf16(utf16, wcslen(utf16));
}

http_internal_wstring utf16_from_utf8(_In_z_ const char* utf8)
{
    return utf16_from_utf8(utf8, strlen(utf8));
}

http_internal_string utf8_from_utf16(_In_reads_(size) PCWSTR utf16, size_t size)
{
    // early out on empty strings since they are trivially convertible
    if (size == 0)
    {
        return "";
    }

    // query for the buffer size
    auto queryResult = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS,
        utf16, static_cast<int>(size),
        nullptr, 0,
        nullptr, nullptr
    );
    if (queryResult == 0)
    {
#if HC_TRACE_ERROR_ENABLE // to avoid unused variable warnings
        auto err = GetLastError();
        HC_TRACE_ERROR(HTTPCLIENT, "utf16_from_uft8 failed during buffer size query with error: %u", err);
#endif
        throw std::exception("utf16_from_utf8 failed");
    }

    // allocate the output buffer, queryResult is the required size
    http_internal_string utf8(static_cast<size_t>(queryResult), L'\0');
    auto conversionResult = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS,
        utf16, static_cast<int>(size),
        &utf8[0], static_cast<int>(utf8.size()),
        nullptr, nullptr
    );
    if (conversionResult == 0)
    {
#if HC_TRACE_ERROR_ENABLE // to avoid unused variable warnings
        auto err = GetLastError();
        HC_TRACE_ERROR(HTTPCLIENT, "utf16_from_uft8 failed during conversion: %u", err);
#endif
        throw std::exception("utf16_from_utf8 failed");
    }

    return utf8;
}

http_internal_wstring utf16_from_utf8(_In_reads_(size) const char* utf8, size_t size)
{
    // early out on empty strings since they are trivially convertible
    if (size == 0)
    {
        return L"";
    }

    // query for the buffer size
    auto queryResult = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS,
        utf8, static_cast<int>(size),
        nullptr, 0
    );
    if (queryResult == 0)
    {
#if HC_TRACE_ERROR_ENABLE // to avoid unused variable warnings
        auto err = GetLastError();
        HC_TRACE_ERROR(HTTPCLIENT, "utf16_from_uft8 failed during buffer size query with error: %u", err);
#endif
        throw std::exception("utf16_from_utf8 failed");
    }

    // allocate the output buffer, queryResult is the required size
    http_internal_wstring utf16(static_cast<size_t>(queryResult), L'\0');
    auto conversionResult = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS,
        utf8, static_cast<int>(size),
        &utf16[0], static_cast<int>(utf16.size())
    );
    if (conversionResult == 0)
    {
#if HC_TRACE_ERROR_ENABLE // to avoid unused variable warnings
        auto err = GetLastError();
        HC_TRACE_ERROR(HTTPCLIENT, "utf16_from_uft8 failed during conversion: %u", err);
#endif
        throw std::exception("utf16_from_utf8 failed");
    }

    return utf16;
}

#if !HC_XDK_API && !HC_UWP_API

NAMESPACE_XBOX_HTTP_CLIENT_BEGIN

static http_internal_unordered_map<proxy_protocol, http_internal_wstring> protocolsMap =
{
    { proxy_protocol::http, L"http" },
    { proxy_protocol::https, L"https" },
    { proxy_protocol::websocket, L"socks" },
    { proxy_protocol::ftp, L"ftp" }
};

proxy_type get_ie_proxy_info(_In_ proxy_protocol protocol, _Inout_ xbox::httpclient::Uri& proxyUri)
{
    proxy_type proxyType = proxy_type::automatic_proxy;

#if HC_PLATFORM != HC_PLATFORM_GDK
    if (IsWindows8Point1OrGreater())
    {
        return proxyType;
    }

    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG config = { 0 };
    if (!WinHttpGetIEProxyConfigForCurrentUser(&config))
    {
        return proxyType;
    }

    if (config.fAutoDetect)
    {
        proxyType = proxy_type::autodiscover_proxy;
    }
    else if (config.lpszProxy != nullptr)
    {
        http_internal_wstring proxyAddress;

        // something like "http=127.0.0.1:8888;https=127.0.0.1:8888", or "localhost:80"
        http_internal_wstring proxyConfig = config.lpszProxy;
        if (proxyConfig.find(L"=") == http_internal_wstring::npos)
        {
            proxyAddress = proxyConfig;
        }
        else
        {
            auto protocolString = protocolsMap[protocol];

            auto pos = proxyConfig.find(protocolString);
            if (pos != http_internal_wstring::npos)
            {
                proxyAddress = proxyConfig.substr(pos + protocolString.length() + 1);
                proxyAddress = proxyAddress.substr(0, proxyConfig.find(';', pos));
            }
        }

        if (!proxyAddress.empty())
        {
            if (proxyAddress.find(L"://") == http_internal_wstring::npos)
            {
                proxyAddress = L"http://" + proxyAddress;
            }
        }

        proxyType = (proxyAddress.empty()) ? proxy_type::no_proxy : proxy_type::named_proxy;
        proxyUri = Uri(utf8_from_utf16(proxyAddress));
    }
    else
    {
        proxyType = proxy_type::no_proxy;
    }
#else
    UNREFERENCED_PARAMETER(protocol);
    UNREFERENCED_PARAMETER(proxyUri);
#endif

    return proxyType;
}

bool convert_proxy_info(_In_ proxy_protocol protocol, _In_ WINHTTP_PROXY_INFO* proxyInfo, _Out_ xbox::httpclient::Uri* outProxyUri)
{
    if (!proxyInfo->lpszProxy)
    {
        return false;
    }

    http_internal_wstring proxyAddress;

    // something like "http=127.0.0.1:8888;https=127.0.0.1:8888", or "localhost:80"
    http_internal_wstring proxyConfig = proxyInfo->lpszProxy;
    if (proxyConfig.find(L"=") == http_internal_wstring::npos)
    {
        proxyAddress = proxyConfig;
    }
    else
    {
        auto protocolString = protocolsMap[protocol];

        auto pos = proxyConfig.find(protocolString);
        if (pos != http_internal_wstring::npos)
        {
            proxyAddress = proxyConfig.substr(pos + protocolString.length() + 1);
            proxyAddress = proxyAddress.substr(0, proxyConfig.find(';', pos));
        }
    }

    if (proxyAddress.empty())
    {
        return false;
    }

    if (proxyAddress.find(L"://") == http_internal_wstring::npos)
    {
        proxyAddress = protocolsMap[protocol] + proxyAddress;
    }

    *outProxyUri = Uri(utf8_from_utf16(proxyAddress));
    return true;
}

bool get_proxy_for_uri(_In_ proxy_protocol protocol, _In_ const xbox::httpclient::Uri& uri, _Out_ xbox::httpclient::Uri* outProxyUri)
{
#if !HC_XDK_API && !HC_UWP_API
    auto singleton = xbox::httpclient::get_http_singleton();
    if (!singleton || !singleton->m_performEnv)
    {
        return false;
    }

    auto winhttpState = singleton->m_performEnv->winHttpState;
    if (!winhttpState)
    {
        return false;
    }

    uint32_t securityFlags = winhttpState->GetDefaultHttpSecurityProtocolFlagsForWin7();
    HINTERNET hSession = winhttpState->GetSessionForHttpSecurityProtocolFlags(securityFlags);
    if (!hSession)
    {
        return false;
    }

    WINHTTP_AUTOPROXY_OPTIONS options = { 0 };
    options.dwFlags = WINHTTP_AUTOPROXY_ALLOW_AUTOCONFIG | WINHTTP_AUTOPROXY_ALLOW_CM | WINHTTP_AUTOPROXY_ALLOW_STATIC;
    options.fAutoLogonIfChallenged = FALSE;

    LPWSTR autoConfigUrl = nullptr;
    if (WinHttpDetectAutoProxyConfigUrl(options.dwAutoDetectFlags, &autoConfigUrl) && autoConfigUrl)
    {
        options.dwFlags |= WINHTTP_AUTOPROXY_CONFIG_URL;
        options.lpszAutoConfigUrl = autoConfigUrl;
    }
    else
    {
        options.dwFlags |= WINHTTP_AUTOPROXY_AUTO_DETECT;
        options.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
    }

    http_internal_wstring wideUri = protocolsMap[protocol];
    wideUri += L"://";
    wideUri += utf16_from_utf8(uri.Authority());
    wideUri += utf16_from_utf8(uri.Resource());

    WINHTTP_PROXY_INFO proxyInfo = { 0 };
    if (!WinHttpGetProxyForUrl(hSession, wideUri.c_str(), &options, &proxyInfo))
    {
        if (GetLastError() == ERROR_WINHTTP_LOGIN_FAILURE)
        {
            options.fAutoLogonIfChallenged = TRUE;
            if (WinHttpGetProxyForUrl(hSession, wideUri.c_str(), &options, &proxyInfo))
            {
                return convert_proxy_info(protocol, &proxyInfo, outProxyUri);
            }
        }
        return false;
    }

    return convert_proxy_info(protocol, &proxyInfo, outProxyUri);
#else
    return false;
#endif
}

NAMESPACE_XBOX_HTTP_CLIENT_END

#endif
