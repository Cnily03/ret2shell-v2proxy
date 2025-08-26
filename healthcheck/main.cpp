#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define close closesocket
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

class HttpClient {
   private:
    bool isValidIPAddress(const std::string& ip) {
        struct sockaddr_in sa;
        int result = inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));
        return result != 0;
    }

    std::string queryDNS(const std::string& hostname, const std::string& dns_server = "8.8.8.8") {
        // Simple DNS query implementation
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            return "";
        }

        struct sockaddr_in dns_addr;
        memset(&dns_addr, 0, sizeof(dns_addr));
        dns_addr.sin_family = AF_INET;
        dns_addr.sin_port = htons(53);
        inet_pton(AF_INET, dns_server.c_str(), &dns_addr.sin_addr);

        // Build DNS query packet
        unsigned char query[512];
        int query_len = 0;

        // DNS header
        query[query_len++] = 0x12;
        query[query_len++] = 0x34;  // Transaction ID
        query[query_len++] = 0x01;
        query[query_len++] = 0x00;  // Flags: standard query
        query[query_len++] = 0x00;
        query[query_len++] = 0x01;  // Questions: 1
        query[query_len++] = 0x00;
        query[query_len++] = 0x00;  // Answer RRs: 0
        query[query_len++] = 0x00;
        query[query_len++] = 0x00;  // Authority RRs: 0
        query[query_len++] = 0x00;
        query[query_len++] = 0x00;  // Additional RRs: 0

        // Question section
        std::string host_copy = hostname;
        size_t pos = 0;
        while ((pos = host_copy.find('.')) != std::string::npos) {
            std::string label = host_copy.substr(0, pos);
            query[query_len++] = label.length();
            memcpy(query + query_len, label.c_str(), label.length());
            query_len += label.length();
            host_copy = host_copy.substr(pos + 1);
        }
        if (!host_copy.empty()) {
            query[query_len++] = host_copy.length();
            memcpy(query + query_len, host_copy.c_str(), host_copy.length());
            query_len += host_copy.length();
        }
        query[query_len++] = 0x00;  // End of hostname
        query[query_len++] = 0x00;
        query[query_len++] = 0x01;  // Type: A
        query[query_len++] = 0x00;
        query[query_len++] = 0x01;  // Class: IN

        // Send query
        if (sendto(sock, (char*)query, query_len, 0, (struct sockaddr*)&dns_addr,
                   sizeof(dns_addr)) < 0) {
            close(sock);
            return "";
        }

        // Receive response
        unsigned char response[512];
        socklen_t addr_len = sizeof(dns_addr);
        int resp_len = recvfrom(sock, (char*)response, sizeof(response), 0,
                                (struct sockaddr*)&dns_addr, &addr_len);
        close(sock);

        if (resp_len < 12) {
            return "";
        }

        // Parse response
        int questions = (response[4] << 8) | response[5];
        int answers = (response[6] << 8) | response[7];

        if (answers == 0) {
            return "";
        }

        // Skip header and question section
        int offset = 12;
        for (int i = 0; i < questions; i++) {
            while (offset < resp_len && response[offset] != 0) {
                offset += response[offset] + 1;
            }
            offset += 5;  // Skip null terminator + type + class
        }

        // Parse answer section
        for (int i = 0; i < answers; i++) {
            if (offset >= resp_len) break;

            // Skip name (could be compressed)
            if ((response[offset] & 0xC0) == 0xC0) {
                offset += 2;  // Compressed name
            } else {
                while (offset < resp_len && response[offset] != 0) {
                    offset += response[offset] + 1;
                }
                offset++;  // Skip null terminator
            }

            if (offset + 10 > resp_len) break;

            int type = (response[offset] << 8) | response[offset + 1];
            int length = (response[offset + 8] << 8) | response[offset + 9];
            offset += 10;

            if (type == 1 && length == 4) {  // A record
                char ip_str[16];
                sprintf(ip_str, "%d.%d.%d.%d", response[offset], response[offset + 1],
                        response[offset + 2], response[offset + 3]);
                return std::string(ip_str);
            }
            offset += length;
        }

        return "";
    }

    std::string resolveHostname(const std::string& hostname) {
        // If it's already an IP address, return it directly
        if (isValidIPAddress(hostname)) {
            return hostname;
        }

        // Try primary DNS server
        std::string resolved_ip = queryDNS(hostname, "8.8.8.8");
        if (resolved_ip.empty()) {
            // Fallback to secondary DNS server
            resolved_ip = queryDNS(hostname, "1.1.1.1");
        }

        if (resolved_ip.empty()) {
            std::cerr << "DNS resolution failed for " << hostname << std::endl;
            return "";
        }

        // std::cout << "Resolved " << hostname << " to " << resolved_ip << std::endl;
        return resolved_ip;
    }

    std::string extractHost(const std::string& url) {
        size_t start = url.find("://");
        if (start == std::string::npos) {
            start = 0;
        } else {
            start += 3;
        }

        size_t end = url.find('/', start);
        size_t port_pos = url.find(':', start);

        if (port_pos != std::string::npos && (end == std::string::npos || port_pos < end)) {
            end = port_pos;
        }

        if (end == std::string::npos) {
            return url.substr(start);
        }
        return url.substr(start, end - start);
    }

    int extractPort(const std::string& url) {
        size_t start = url.find("://");
        if (start == std::string::npos) {
            start = 0;
        } else {
            start += 3;
        }

        size_t port_pos = url.find(':', start);
        if (port_pos == std::string::npos) {
            return (url.substr(0, 5) == "https") ? 443 : 80;
        }

        size_t end = url.find('/', port_pos);
        if (end == std::string::npos) {
            end = url.length();
        }

        std::string port_str = url.substr(port_pos + 1, end - port_pos - 1);
        return std::atoi(port_str.c_str());
    }

    std::string extractPath(const std::string& url) {
        size_t start = url.find("://");
        if (start == std::string::npos) {
            start = 0;
        } else {
            start += 3;
        }

        size_t path_pos = url.find('/', start);
        if (path_pos == std::string::npos) {
            return "/";
        }
        return url.substr(path_pos);
    }

   public:
    int sendGetRequest(const std::string& url) {
        std::string host = extractHost(url);
        int port = extractPort(url);
        std::string path = extractPath(url);

#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "WSAStartup failed" << std::endl;
            return -1;
        }
#endif

        // Resolve hostname to IP address
        std::string resolved_ip = resolveHostname(host);
        if (resolved_ip.empty()) {
            std::cerr << "Failed to resolve hostname: " << host << std::endl;
#ifdef _WIN32
            WSACleanup();
#endif
            return -1;
        }

        // Create socket
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            std::cerr << "Socket creation failed" << std::endl;
#ifdef _WIN32
            WSACleanup();
#endif
            return -1;
        }

        // Setup server address with resolved IP
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        if (inet_pton(AF_INET, resolved_ip.c_str(), &server_addr.sin_addr) <= 0) {
            std::cerr << "Invalid IP address: " << resolved_ip << std::endl;
            close(sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return -1;
        }

        // Connect to server
        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Connection failed to " << host << " (" << resolved_ip << "):" << port
                      << std::endl;
            close(sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return -1;
        }

        // Build HTTP GET request
        std::string request = "GET " + path + " HTTP/1.1\r\n";
        request += "Host: " + host + "\r\n";
        request += "User-Agent: HealthCheck/1.0\r\n";
        request += "Connection: close\r\n";
        request += "\r\n";

        // Send request
        if (send(sock, request.c_str(), request.length(), 0) < 0) {
            std::cerr << "Failed to send request" << std::endl;
            close(sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return -1;
        }

        // Receive response
        char buffer[4096];
        int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0) {
            std::cerr << "Failed to receive response" << std::endl;
            close(sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return -1;
        }

        buffer[bytes_received] = '\0';
        std::string response(buffer);

        // Close socket
        close(sock);
#ifdef _WIN32
        WSACleanup();
#endif

        // Parse HTTP status code
        size_t status_pos = response.find("HTTP/");
        if (status_pos == std::string::npos) {
            std::cerr << "Invalid HTTP response" << std::endl;
            return -1;
        }

        size_t code_start = response.find(' ', status_pos);
        if (code_start == std::string::npos) {
            std::cerr << "Invalid HTTP response format" << std::endl;
            return -1;
        }

        code_start++;
        size_t code_end = response.find(' ', code_start);
        if (code_end == std::string::npos) {
            std::cerr << "Invalid HTTP response format" << std::endl;
            return -1;
        }

        std::string status_code_str = response.substr(code_start, code_end - code_start);
        int status_code = std::atoi(status_code_str.c_str());

        // std::cout << "HTTP Status Code: " << status_code << std::endl;

        return status_code;
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <URL>" << std::endl;
        std::cerr << "Example: " << argv[0] << " http://localhost:1331/health" << std::endl;
        return 1;
    }

    std::string url = argv[1];
    HttpClient client;

    int status_code = client.sendGetRequest(url);

    if (status_code == 200) {
        std::cout << "Health check passed (HTTP 200)" << std::endl;
        return 0;
    } else if (status_code > 0) {
        std::cout << "Health check failed (HTTP " << status_code << ")" << std::endl;
        return 1;
    } else {
        std::cout << "Health check failed (Network error)" << std::endl;
        return 1;
    }
}