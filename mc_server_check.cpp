/*
 * Minecraft Java版服务器连接诊断工具
 * 功能：
 *   1. DNS 检测
 *   2. 端口TCP连通性检测 (SRV解析)
 *   3. Minecraft 握手检测
 *   4. 客户端本机网络检查
 *   5. 输出检测报告
 */

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
    bool mcHandshakeSuccess = false;
    std::string mcServerVersion;
    std::string mcMotd;
    int mcOnlinePlayers = -1;
    int mcMaxPlayers = -1;
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

// 写入VarInt
int WriteVarInt(unsigned char* buffer, int value) {
    int written = 0;
    while (true) {
        if ((value & ~0x7F) == 0) {
            buffer[written++] = (unsigned char)value;
            return written;
        }
        buffer[written++] = (unsigned char)((value & 0x7F) | 0x80);
        value = ((unsigned int)value) >> 7;
    }
}

// 读取VarInt
int ReadVarInt(const unsigned char* buffer, int& bytesRead) {
    int value = 0;
    int shift = 0;
    bytesRead = 0;
    
    while (true) {
        unsigned char b = buffer[bytesRead++];
        value |= (b & 0x7F) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
        if (shift >= 32) break;
    }
    
    return value;
}

// Minecraft握手协议测试
bool TestMinecraftHandshake(const std::string& ip, int port, std::string& version, std::string& motd, int& online, int& maxPlayers) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return false;
    }
    
    // 设置超时
    int timeout = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    
    struct sockaddr_in server = {};
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &server.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }
    
    // 构建握手包
    unsigned char packet[512];
    int packetLen = 0;
    
    // 包内容
    unsigned char content[256];
    int contentLen = 0;
    
    // 包ID (0x00 for handshake)
    content[contentLen++] = 0x00;
    
    // 协议版本 (使用-1表示状态请求)
    contentLen += WriteVarInt(content + contentLen, -1);
    
    // 服务器地址
    int hostLen = (int)ip.length();
    contentLen += WriteVarInt(content + contentLen, hostLen);
    memcpy(content + contentLen, ip.c_str(), hostLen);
    contentLen += hostLen;
    
    // 端口
    content[contentLen++] = (port >> 8) & 0xFF;
    content[contentLen++] = port & 0xFF;
    
    // 下一个状态 (1 = status)
    contentLen += WriteVarInt(content + contentLen, 1);
    
    // 写入包长度
    packetLen = WriteVarInt(packet, contentLen);
    memcpy(packet + packetLen, content, contentLen);
    packetLen += contentLen;
    
    // 发送握手包
    if (send(sock, (const char*)packet, packetLen, 0) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }
    
    // 发送状态请求包 (0x00)
    unsigned char statusRequest[2];
    statusRequest[0] = 1; // 包长度
    statusRequest[1] = 0x00; // 包ID
    
    if (send(sock, (const char*)statusRequest, 2, 0) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }
    
    // 接收响应
    unsigned char recvBuffer[65536];
    int totalReceived = 0;
    int bytesReceived;
    
    // 读取响应
    bytesReceived = recv(sock, (char*)recvBuffer, sizeof(recvBuffer), 0);
    if (bytesReceived <= 0) {
        closesocket(sock);
        return false;
    }
    totalReceived = bytesReceived;
    
    closesocket(sock);
    
    // 解析响应
    int offset = 0;
    int bytesRead;
    
    // 读取包长度
    int responsePacketLen = ReadVarInt(recvBuffer + offset, bytesRead);
    offset += bytesRead;
    
    // 读取包ID
    int responsePacketId = ReadVarInt(recvBuffer + offset, bytesRead);
    offset += bytesRead;
    
    if (responsePacketId != 0x00) {
        return false;
    }
    
    // 读取JSON字符串长度
    int jsonLen = ReadVarInt(recvBuffer + offset, bytesRead);
    offset += bytesRead;
    
    if (jsonLen <= 0 || offset + jsonLen > totalReceived) {
        return false;
    }
    
    std::string jsonResponse((char*)recvBuffer + offset, jsonLen);
    
    // 简单解析JSON (不使用外部库)
    // 查找版本
    size_t versionPos = jsonResponse.find("\"name\"");
    if (versionPos != std::string::npos) {
        size_t start = jsonResponse.find(':', versionPos);
        if (start != std::string::npos) {
            start = jsonResponse.find('"', start + 1);
            if (start != std::string::npos) {
                size_t end = jsonResponse.find('"', start + 1);
                if (end != std::string::npos) {
                    version = jsonResponse.substr(start + 1, end - start - 1);
                }
            }
        }
    }
    
    // 查找MOTD (description)
    size_t descPos = jsonResponse.find("\"description\"");
    if (descPos != std::string::npos) {
        size_t start = jsonResponse.find(':', descPos);
        if (start != std::string::npos) {
            // 可能是字符串或对象
            size_t nextChar = jsonResponse.find_first_not_of(" \t\n\r", start + 1);
            if (nextChar != std::string::npos) {
                if (jsonResponse[nextChar] == '"') {
                    size_t end = jsonResponse.find('"', nextChar + 1);
                    if (end != std::string::npos) {
                        motd = jsonResponse.substr(nextChar + 1, end - nextChar - 1);
                    }
                } else if (jsonResponse[nextChar] == '{') {
                    // 对象形式的description，查找text字段
                    size_t textPos = jsonResponse.find("\"text\"", nextChar);
                    if (textPos != std::string::npos) {
                        size_t textStart = jsonResponse.find('"', textPos + 6);
                        if (textStart != std::string::npos) {
                            size_t textEnd = jsonResponse.find('"', textStart + 1);
                            if (textEnd != std::string::npos) {
                                motd = jsonResponse.substr(textStart + 1, textEnd - textStart - 1);
                            }
                        }
                    }
                }
            }
        }
    }
    
    // 查找在线玩家数
    size_t onlinePos = jsonResponse.find("\"online\"");
    if (onlinePos != std::string::npos) {
        size_t start = jsonResponse.find(':', onlinePos);
        if (start != std::string::npos) {
            online = std::stoi(jsonResponse.substr(start + 1));
        }
    }
    
    // 查找最大玩家数
    size_t maxPos = jsonResponse.find("\"max\"");
    if (maxPos != std::string::npos) {
        size_t start = jsonResponse.find(':', maxPos);
        if (start != std::string::npos) {
            maxPlayers = std::stoi(jsonResponse.substr(start + 1));
        }
    }
    
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
    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << "       Minecraft 服务器连接诊断报告     \n";
    std::cout << "========================================\n\n";
    
    std::cout << "【基本信息】\n";
    std::cout << "服务器域名：" << result.serverDomain << "\n";
    
    if (result.srvFound) {
        std::cout << "SRV记录：" << result.srvTarget << ":" << result.srvPort << "\n";
    }
    
    if (result.dnsSuccess) {
        std::cout << "解析IP：" << result.resolvedIP << ":" << result.port << "\n";
    } else {
        std::cout << "解析IP：解析失败\n";
    }
    
    std::cout << "\n【连通性检测】\n";
    
    // Ping状态
    std::cout << "Ping：";
    if (result.pingSuccess) {
        std::cout << result.pingLatencyMs << "ms\n";
    } else {
        std::cout << "超时/不可达\n";
    }
    
    // TCP连接状态
    std::cout << "TCP连接：";
    if (result.tcpConnectable) {
        std::cout << "成功 (" << result.tcpLatencyMs << "ms)\n";
    } else {
        std::cout << "失败\n";
    }
    
    // MC握手状态
    std::cout << "MC握手：";
    if (result.mcHandshakeSuccess) {
        std::cout << "成功\n";
        std::cout << "  服务器版本：" << result.mcServerVersion << "\n";
        if (!result.mcMotd.empty()) {
            std::cout << "  服务器MOTD：" << result.mcMotd << "\n";
        }
        if (result.mcOnlinePlayers >= 0) {
            std::cout << "  在线玩家：" << result.mcOnlinePlayers << "/" << result.mcMaxPlayers << "\n";
        }
    } else {
        std::cout << "未收到服务器响应\n";
    }
    
    std::cout << "\n【诊断结果】\n";
    
    // DNS检测结果
    if (result.dnsSuccess) {
        std::cout << "[OK] DNS解析正常\n";
    } else {
        std::cout << "[X] DNS解析失败（请尝试修改DNS或检查域名是否正确）\n";
    }
    
    // 本地网络检测
    if (result.localNetworkOk) {
        std::cout << "[OK] 本地网络正常\n";
    } else {
        std::cout << "[X] 本地网络异常（请检查网络连接）\n";
    }
    
    // Ping检测结果
    if (result.pingSuccess) {
        std::cout << "[OK] Ping正常\n";
    } else if (result.dnsSuccess) {
        std::cout << "[!] Ping不通（服务器可能禁用了ICMP或被网络屏蔽）\n";
    }
    
    // TCP检测结果
    if (result.tcpConnectable) {
        std::cout << "[OK] TCP端口可达\n";
    } else if (result.dnsSuccess) {
        std::cout << "[X] TCP端口不可达\n";
    }
    
    // MC握手结果
    if (result.mcHandshakeSuccess) {
        std::cout << "[OK] Minecraft服务器响应正常\n";
    } else if (result.tcpConnectable) {
        std::cout << "[X] 未收到Minecraft服务器握手响应\n";
    }
    
    // 输出可能的原因
    if (!result.possibleReasons.empty()) {
        std::cout << "\n【可能的原因】\n";
        for (size_t i = 0; i < result.possibleReasons.size(); i++) {
            std::cout << (i + 1) << ". " << result.possibleReasons[i] << "\n";
        }
    }
    
    // 综合结论
    std::cout << "\n【综合结论】\n";
    if (result.mcHandshakeSuccess) {
        std::cout << ">>> 服务器运行正常，可以正常连接！\n";
    } else if (!result.localNetworkOk) {
        std::cout << ">>> 您的本地网络存在问题，请先检查网络连接。\n";
    } else if (!result.dnsSuccess) {
        std::cout << ">>> 域名解析失败，请检查服务器地址是否正确或尝试更换DNS。\n";
    } else if (!result.tcpConnectable) {
        std::cout << ">>> 无法连接到服务器端口，服务器可能未开启或端口被屏蔽。\n";
    } else {
        std::cout << ">>> TCP连接成功但MC握手失败，服务器可能不是Minecraft服务器或版本不兼容。\n";
    }
    
    std::cout << "\n========================================\n";
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
    
    if (result.tcpConnectable && !result.mcHandshakeSuccess) {
        result.possibleReasons.push_back("该端口上运行的可能不是Minecraft服务器");
        result.possibleReasons.push_back("服务器正在启动中，尚未完全加载");
        result.possibleReasons.push_back("服务器版本过旧，不支持当前的查询协议");
        result.possibleReasons.push_back("服务器安装了禁止查询的插件");
    }
}

// 执行完整诊断
DiagnosticResult PerformDiagnostic(const std::string& serverAddress) {
    DiagnosticResult result;
    
    std::cout << "\n正在诊断服务器: " << serverAddress << "\n";
    std::cout << "----------------------------------------\n";
    
    // 解析地址
    ParseServerAddress(serverAddress, result.serverDomain, result.port);
    
    // 1. 检查本地网络
    std::cout << "[1/5] 检查本地网络... ";
    result.localNetworkOk = CheckLocalNetwork();
    std::cout << (result.localNetworkOk ? "正常" : "异常") << "\n";
    
    if (!result.localNetworkOk) {
        AnalyzeProblem(result);
        return result;
    }
    
    // 2. 查询SRV记录
    std::cout << "[2/5] 查询SRV记录... ";
    result.srvFound = QuerySRVRecord(result.serverDomain, result.srvTarget, result.srvPort);
    if (result.srvFound) {
        std::cout << "找到 (" << result.srvTarget << ":" << result.srvPort << ")\n";
        result.serverDomain = result.srvTarget;
        result.port = result.srvPort;
    } else {
        std::cout << "未找到（使用默认端口）\n";
    }
    
    // 3. DNS解析
    std::cout << "[3/5] DNS解析... ";
    result.dnsSuccess = ResolveDNS(result.serverDomain, result.resolvedIP);
    if (result.dnsSuccess) {
        std::cout << result.resolvedIP << "\n";
    } else {
        std::cout << "失败\n";
        AnalyzeProblem(result);
        return result;
    }
    
    // 4. Ping测试
    std::cout << "[4/5] Ping测试... ";
    result.pingSuccess = TestPing(result.resolvedIP, result.pingLatencyMs);
    if (result.pingSuccess) {
        std::cout << result.pingLatencyMs << "ms\n";
    } else {
        std::cout << "超时\n";
    }
    
    // 5. TCP连接测试
    std::cout << "[5/5] TCP连接测试... ";
    result.tcpConnectable = TestTCPConnection(result.resolvedIP, result.port, result.tcpLatencyMs);
    if (result.tcpConnectable) {
        std::cout << "成功 (" << result.tcpLatencyMs << "ms)\n";
    } else {
        std::cout << "失败\n";
        AnalyzeProblem(result);
        return result;
    }
    
    // 6. Minecraft握手测试
    std::cout << "[6/6] Minecraft握手测试... ";
    result.mcHandshakeSuccess = TestMinecraftHandshake(
        result.resolvedIP, result.port,
        result.mcServerVersion, result.mcMotd,
        result.mcOnlinePlayers, result.mcMaxPlayers
    );
    if (result.mcHandshakeSuccess) {
        std::cout << "成功\n";
    } else {
        std::cout << "失败\n";
    }
    
    AnalyzeProblem(result);
    return result;
}

int main() {
    // 设置控制台编码为UTF-8
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    
    // 启用虚拟终端处理以支持ANSI转义序列
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    
    std::cout << "+--------------------------------------------+\n";
    std::cout << "|  Minecraft Java版 服务器连接诊断工具 v1.0  |\n";
    std::cout << "+--------------------------------------------+\n\n";
    
    if (!InitWinsock()) {
        std::cerr << "错误：无法初始化网络组件\n";
        return 1;
    }
    
    std::string serverAddress;
    
    while (true) {
        std::cout << "请输入服务器地址（例如: gddx.sakura.ink）\n";
        std::cout << "输入 'quit' 退出程序\n";
        std::cout << "> ";
        
        std::getline(std::cin, serverAddress);
        
        // 去除首尾空格
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
            std::cout << "请输入有效的服务器地址\n\n";
            continue;
        }
        
        DiagnosticResult result = PerformDiagnostic(serverAddress);
        GenerateReport(result);
        
        std::cout << "\n";
    }
    
    CleanupWinsock();
    std::cout << "\n感谢使用，再见！\n";
    
    return 0;
}
