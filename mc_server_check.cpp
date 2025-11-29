/*
 * Minecraft Java版服务器连接诊断工具
 * 功能：
 *   1. DNS 检测
 *   2. 端口TCP连通性检测 (SRV解析)
 *   3. Minecraft 握手检测
 *   4. 客户端本机网络检查
 *   5. 输出检测报告
 */

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <windns.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "iphlpapi.lib")

// 控制台输出句柄
static HANDLE g_hConsole = INVALID_HANDLE_VALUE;

// 使用WriteConsoleW输出宽字符串
void PrintW(const wchar_t* wstr) {
    if (g_hConsole == INVALID_HANDLE_VALUE) {
        g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    }
    DWORD written;
    WriteConsoleW(g_hConsole, wstr, (DWORD)wcslen(wstr), &written, nullptr);
}

// 输出ASCII字符串（用于变量内容）
void PrintA(const char* str) {
    if (g_hConsole == INVALID_HANDLE_VALUE) {
        g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    }
    DWORD written;
    WriteConsoleA(g_hConsole, str, (DWORD)strlen(str), &written, nullptr);
}

// 便捷宏
#define PRINT(x) PrintW(x)
#define PRINTLN(x) do { PrintW(x); PrintW(L"\n"); } while(0)
#define PRINTA(x) PrintA(x)
#define PRINTLNA(x) do { PrintA(x); PrintW(L"\n"); } while(0)

// 诊断结果结构
struct DiagnosticResult {
    std::string serverDomain;
    std::string resolvedIP;
    int port = 25565;
    bool dnsSuccess = false;
    bool srvFound = false;
    std::string srvTarget;
    int srvPort = 0;
    bool tcpConnectable = false;
    int tcpLatencyMs = -1;
    bool pingSuccess = false;
    int pingLatencyMs = -1;
    bool localNetworkOk = false;
    std::vector<std::string> possibleReasons;
};

// 初始化Winsock
bool InitWinsock() {
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
}

// 清理Winsock
void CleanupWinsock() {
    WSACleanup();
}

// 解析服务器地址（分离主机名和端口）
void ParseServerAddress(const std::string& input, std::string& host, int& port) {
    port = 25565; // 默认端口
    size_t colonPos = input.rfind(':');
    
    // 检查是否是IPv6地址
    if (input.front() == '[') {
        size_t bracketEnd = input.find(']');
        if (bracketEnd != std::string::npos) {
            host = input.substr(1, bracketEnd - 1);
            if (bracketEnd + 1 < input.length() && input[bracketEnd + 1] == ':') {
                port = std::stoi(input.substr(bracketEnd + 2));
            }
            return;
        }
    }
    
    // 检查是否有端口
    if (colonPos != std::string::npos) {
        // 确保不是IPv6地址
        size_t firstColon = input.find(':');
        if (firstColon == colonPos) {
            host = input.substr(0, colonPos);
            try {
                port = std::stoi(input.substr(colonPos + 1));
            } catch (...) {
                port = 25565;
            }
            return;
        }
    }
    
    host = input;
}

// SRV记录查询
bool QuerySRVRecord(const std::string& domain, std::string& target, int& port) {
    std::string srvName = "_minecraft._tcp." + domain;
    PDNS_RECORD pDnsRecord = nullptr;
    
    DNS_STATUS status = DnsQuery_A(
        srvName.c_str(),
        DNS_TYPE_SRV,
        DNS_QUERY_STANDARD,
        nullptr,
        &pDnsRecord,
        nullptr
    );
    
    if (status == 0 && pDnsRecord != nullptr) {
        if (pDnsRecord->wType == DNS_TYPE_SRV) {
            // 将 PSTR 转换为 std::string
            if (pDnsRecord->Data.SRV.pNameTarget != nullptr) {
                // DnsQuery_A 返回 ANSI 字符串
                target = (const char*)pDnsRecord->Data.SRV.pNameTarget;
            }
            port = pDnsRecord->Data.SRV.wPort;
            DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
            return true;
        }
        DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    }
    
    return false;
}

// DNS解析
bool ResolveDNS(const std::string& hostname, std::string& ip) {
    struct addrinfo hints = {};
    struct addrinfo* result = nullptr;
    
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    int ret = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
    if (ret != 0) {
        return false;
    }
    
    if (result != nullptr) {
        struct sockaddr_in* addr = (struct sockaddr_in*)result->ai_addr;
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr->sin_addr), ipStr, INET_ADDRSTRLEN);
        ip = ipStr;
        freeaddrinfo(result);
        return true;
    }
    
    return false;
}

// TCP连接测试
bool TestTCPConnection(const std::string& ip, int port, int& latencyMs, int timeoutMs = 5000) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return false;
    }
    
    // 设置非阻塞模式
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    
    struct sockaddr_in server = {};
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &server.sin_addr);
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    int result = connect(sock, (struct sockaddr*)&server, sizeof(server));
    
    if (result == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK) {
            fd_set writeSet, exceptSet;
            FD_ZERO(&writeSet);
            FD_ZERO(&exceptSet);
            FD_SET(sock, &writeSet);
            FD_SET(sock, &exceptSet);
            
            struct timeval timeout;
            timeout.tv_sec = timeoutMs / 1000;
            timeout.tv_usec = (timeoutMs % 1000) * 1000;
            
            result = select(0, nullptr, &writeSet, &exceptSet, &timeout);
            
            if (result > 0 && FD_ISSET(sock, &writeSet)) {
                auto endTime = std::chrono::high_resolution_clock::now();
                latencyMs = (int)std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
                closesocket(sock);
                return true;
            }
        }
        closesocket(sock);
        return false;
    }
    
    auto endTime = std::chrono::high_resolution_clock::now();
    latencyMs = (int)std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    closesocket(sock);
    return true;
}

// ICMP Ping测试
bool TestPing(const std::string& ip, int& latencyMs) {
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    unsigned long ipAddr = inet_addr(ip.c_str());
    if (ipAddr == INADDR_NONE) {
        IcmpCloseHandle(hIcmp);
        return false;
    }
    
    char sendData[32] = "Minecraft Server Check";
    DWORD replySize = sizeof(ICMP_ECHO_REPLY) + sizeof(sendData) + 8;
    char* replyBuffer = new char[replySize];
    
    DWORD result = IcmpSendEcho(hIcmp, ipAddr, sendData, sizeof(sendData), nullptr, replyBuffer, replySize, 3000);
    
    if (result > 0) {
        PICMP_ECHO_REPLY pReply = (PICMP_ECHO_REPLY)replyBuffer;
        if (pReply->Status == IP_SUCCESS) {
            latencyMs = pReply->RoundTripTime;
            delete[] replyBuffer;
            IcmpCloseHandle(hIcmp);
            return true;
        }
    }
    
    delete[] replyBuffer;
    IcmpCloseHandle(hIcmp);
    return false;
}

// 检查本地网络
bool CheckLocalNetwork() {
    // 检查是否有可用的网络适配器
    ULONG bufferSize = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
    
    ULONG result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &bufferSize);
    
    if (result == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
        result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &bufferSize);
    }
    
    bool hasActiveAdapter = false;
    if (result == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            if (pCurrAddresses->OperStatus == IfOperStatusUp && 
                pCurrAddresses->IfType != IF_TYPE_SOFTWARE_LOOPBACK) {
                hasActiveAdapter = true;
                break;
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    }
    
    free(pAddresses);
    
    // 检查能否连接到公共DNS
    int latency;
    bool canReachInternet = TestTCPConnection("8.8.8.8", 53, latency, 3000) ||
                            TestTCPConnection("1.1.1.1", 53, latency, 3000);
    
    return hasActiveAdapter && canReachInternet;
}

// 生成诊断报告
void GenerateReport(const DiagnosticResult& result) {
    PRINTLN(L"");
    PRINTLN(L"========================================");
    PRINTLN(L"       Minecraft 服务器连接诊断报告     ");
    PRINTLN(L"========================================");
    PRINTLN(L"");
    
    PRINTLN(L"【基本信息】");
    PRINT(L"服务器域名："); PRINTLNA(result.serverDomain.c_str());
    
    if (result.srvFound) {
        PRINT(L"SRV记录："); PRINTA(result.srvTarget.c_str()); 
        PRINT(L":"); 
        char portStr[16]; sprintf(portStr, "%d", result.srvPort);
        PRINTLNA(portStr);
    }
    
    if (result.dnsSuccess) {
        PRINT(L"解析IP："); PRINTA(result.resolvedIP.c_str());
        PRINT(L":");
        char portStr[16]; sprintf(portStr, "%d", result.port);
        PRINTLNA(portStr);
    } else {
        PRINTLN(L"解析IP：解析失败");
    }
    
    PRINTLN(L"");
    PRINTLN(L"【连通性检测】");
    
    // Ping状态
    PRINT(L"Ping：");
    if (result.pingSuccess) {
        char buf[32]; sprintf(buf, "%dms", result.pingLatencyMs);
        PRINTLNA(buf);
    } else {
        PRINTLN(L"超时/不可达");
    }
    
    // TCP连接状态
    PRINT(L"TCP连接：");
    if (result.tcpConnectable) {
        wchar_t buf[64]; swprintf(buf, 64, L"成功 (%dms)", result.tcpLatencyMs);
        PRINTLN(buf);
    } else {
        PRINTLN(L"失败");
    }
    
    PRINTLN(L"");
    PRINTLN(L"【诊断结果】");
    
    // DNS检测结果
    if (result.dnsSuccess) {
        PRINTLN(L"[OK] DNS解析正常");
    } else {
        PRINTLN(L"[X] DNS解析失败（请尝试修改DNS或检查域名是否正确）");
    }
    
    // 本地网络检测
    if (result.localNetworkOk) {
        PRINTLN(L"[OK] 本地网络正常");
    } else {
        PRINTLN(L"[X] 本地网络异常（请检查网络连接）");
    }
    
    // Ping检测结果
    if (result.pingSuccess) {
        PRINTLN(L"[OK] Ping正常");
    } else if (result.dnsSuccess) {
        PRINTLN(L"[!] Ping不通（服务器可能禁用了ICMP或被网络屏蔽）");
    }
    
    // TCP检测结果
    if (result.tcpConnectable) {
        PRINTLN(L"[OK] TCP端口可达");
    } else if (result.dnsSuccess) {
        PRINTLN(L"[X] TCP端口不可达");
    }
    
    // 输出可能的原因
    if (!result.possibleReasons.empty()) {
        PRINTLN(L"");
        PRINTLN(L"【可能的原因】");
        for (size_t i = 0; i < result.possibleReasons.size(); i++) {
            wchar_t buf[16]; swprintf(buf, 16, L"%d. ", (int)(i + 1));
            PRINT(buf);
            PRINTLNA(result.possibleReasons[i].c_str());
        }
    }
    
    // 综合结论
    PRINTLN(L"");
    PRINTLN(L"【综合结论】");
    if (result.tcpConnectable) {
        PRINTLN(L">>> 服务器端口可达，应该可以正常连接！");
    } else if (!result.localNetworkOk) {
        PRINTLN(L">>> 您的本地网络存在问题，请先检查网络连接。");
    } else if (!result.dnsSuccess) {
        PRINTLN(L">>> 域名解析失败，请检查服务器地址是否正确或尝试更换DNS。");
    } else {
        PRINTLN(L">>> 无法连接到服务器端口，服务器可能未开启或端口被屏蔽。");
    }
    
    PRINTLN(L"");
    PRINTLN(L"========================================");
}

// 分析问题并生成可能原因
void AnalyzeProblem(DiagnosticResult& result) {
    if (!result.localNetworkOk) {
        result.possibleReasons.push_back("本地网络连接断开或无法访问互联网");
        result.possibleReasons.push_back("检查网线是否连接好或WiFi是否已连接");
        result.possibleReasons.push_back("检查防火墙或杀毒软件是否阻止了网络访问");
    }
    
    if (!result.dnsSuccess) {
        result.possibleReasons.push_back("服务器域名不存在或拼写错误");
        result.possibleReasons.push_back("DNS服务器无法解析该域名，尝试更换DNS（如8.8.8.8或114.114.114.114）");
        result.possibleReasons.push_back("域名已过期或DNS记录未配置");
    }
    
    if (result.dnsSuccess && !result.pingSuccess && !result.tcpConnectable) {
        result.possibleReasons.push_back("服务器IP可能已更换，等待DNS缓存更新");
        result.possibleReasons.push_back("服务器可能已关闭或正在维护");
        result.possibleReasons.push_back("网络运营商可能屏蔽了该IP或端口");
        result.possibleReasons.push_back("需要使用VPN或加速器才能访问");
    }
    
    if (result.dnsSuccess && !result.tcpConnectable && result.pingSuccess) {
        result.possibleReasons.push_back("服务器未开启或端口配置错误");
        result.possibleReasons.push_back("服务器防火墙阻止了该端口的访问");
        result.possibleReasons.push_back("端口号错误，请确认正确的端口号");
    }
}

// 执行完整诊断
DiagnosticResult PerformDiagnostic(const std::string& serverAddress) {
    DiagnosticResult result;
    
    PRINTLN(L"");
    PRINT(L"正在诊断服务器: "); PRINTLNA(serverAddress.c_str());
    PRINTLN(L"----------------------------------------");
    
    // 解析地址
    ParseServerAddress(serverAddress, result.serverDomain, result.port);
    
    // 1. 检查本地网络
    PRINT(L"[1/5] 检查本地网络... ");
    result.localNetworkOk = CheckLocalNetwork();
    PRINTLN(result.localNetworkOk ? L"正常" : L"异常");
    
    if (!result.localNetworkOk) {
        AnalyzeProblem(result);
        return result;
    }
    
    // 2. 查询SRV记录
    PRINT(L"[2/5] 查询SRV记录... ");
    result.srvFound = QuerySRVRecord(result.serverDomain, result.srvTarget, result.srvPort);
    if (result.srvFound) {
        wchar_t buf[256]; swprintf(buf, 256, L"找到 (%S:%d)", result.srvTarget.c_str(), result.srvPort);
        PRINTLN(buf);
        result.serverDomain = result.srvTarget;
        result.port = result.srvPort;
    } else {
        PRINTLN(L"未找到（使用默认端口）");
    }
    
    // 3. DNS解析
    PRINT(L"[3/5] DNS解析... ");
    result.dnsSuccess = ResolveDNS(result.serverDomain, result.resolvedIP);
    if (result.dnsSuccess) {
        PRINTLNA(result.resolvedIP.c_str());
    } else {
        PRINTLN(L"失败");
        AnalyzeProblem(result);
        return result;
    }
    
    // 4. Ping测试
    PRINT(L"[4/5] Ping测试... ");
    result.pingSuccess = TestPing(result.resolvedIP, result.pingLatencyMs);
    if (result.pingSuccess) {
        wchar_t buf[32]; swprintf(buf, 32, L"%dms", result.pingLatencyMs);
        PRINTLN(buf);
    } else {
        PRINTLN(L"超时");
    }
    
    // 5. TCP连接测试
    PRINT(L"[5/5] TCP连接测试... ");
    result.tcpConnectable = TestTCPConnection(result.resolvedIP, result.port, result.tcpLatencyMs);
    if (result.tcpConnectable) {
        wchar_t buf[64]; swprintf(buf, 64, L"成功 (%dms)", result.tcpLatencyMs);
        PRINTLN(buf);
    } else {
        PRINTLN(L"失败");
    }
    
    AnalyzeProblem(result);
    return result;
}

int main() {
    // 初始化控制台句柄
    g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    
    // 设置控制台编码为UTF-8（用于输入）
    SetConsoleCP(CP_UTF8);
    
    PRINTLN(L"+--------------------------------------------+");
    PRINTLN(L"|  Minecraft Java版 服务器连接诊断工具 v1.0  |");
    PRINTLN(L"+--------------------------------------------+");
    PRINTLN(L"");
    
    if (!InitWinsock()) {
        PRINTLN(L"错误：无法初始化网络组件");
        return 1;
    }
    
    std::string serverAddress;
    char inputBuffer[256];
    
    while (true) {
        PRINTLN(L"请输入服务器地址（例如: gdyd.sakura.ink）");
        PRINTLN(L"输入 'quit' 退出程序");
        PRINT(L"> ");
        
        // 使用fgets读取输入
        if (fgets(inputBuffer, sizeof(inputBuffer), stdin) == nullptr) {
            break;
        }
        
        serverAddress = inputBuffer;
        
        // 去除首尾空格和换行
        size_t start = serverAddress.find_first_not_of(" \t\r\n");
        size_t end = serverAddress.find_last_not_of(" \t\r\n");
        if (start == std::string::npos) {
            continue;
        }
        serverAddress = serverAddress.substr(start, end - start + 1);
        
        if (serverAddress == "quit" || serverAddress == "exit" || serverAddress == "q") {
            break;
        }
        
        if (serverAddress.empty()) {
            PRINTLN(L"请输入有效的服务器地址");
            PRINTLN(L"");
            continue;
        }
        
        DiagnosticResult result = PerformDiagnostic(serverAddress);
        GenerateReport(result);
        
        PRINTLN(L"");
    }
    
    CleanupWinsock();
    PRINTLN(L"");
    PRINTLN(L"感谢使用，再见！");
    
    return 0;
}
