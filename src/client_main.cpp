#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>

#include "icmp_tunnel.hpp"

int main(int argc, char* argv[]) {
    int sockfd = -1;
    try {
        if (argc < 3) {
            std::cerr << "Использование: " << argv[0] << " <IP сервера> <команда или /путь/к/файлу>"
                      << std::endl;
            return 1;
        }

        std::string target_ip = argv[1];

        if (!tunnel::IcmpUtils::is_valid_ipv4(target_ip)) {
            throw tunnel::NetworkException("Некорректный IPv4 адрес сервера: " + target_ip);
        }

        std::string command_or_path = argv[2];

        if (command_or_path.empty())
            throw tunnel::NetworkException("Третий аргумент не должен быть пустой строкой");

        std::string command;

        std::ifstream check_file(command_or_path);
        if (check_file.is_open()) {
            check_file.close();
            command = tunnel::IcmpUtils::read_from_file(command_or_path);
            if (!command.empty() && command.back() == '\n') command.pop_back();
            std::cout << "Команда прочитана из файла: " << command_or_path << std::endl;
        } else {
            command = command_or_path;
        }

        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sockfd < 0)
            throw tunnel::NetworkException("Не удалось создать сокет, необходим запуск с root");

        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            throw tunnel::NetworkException("Не удалось установить таймаут на сокет");
        }

        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        inet_pton(AF_INET, target_ip.c_str(), &dest_addr.sin_addr);

        std::vector<uint8_t> payload =
            tunnel::IcmpUtils::wrap_payload(command, tunnel::IcmpUtils::MAGIC_REQ);
        tunnel::IcmpUtils::validate_payload_size(payload.size());
        std::vector<uint8_t> packet(sizeof(struct icmphdr) + payload.size());

        struct icmphdr* icmp = reinterpret_cast<struct icmphdr*>(packet.data());
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = htons(55555);
        icmp->un.echo.sequence = htons(1);
        icmp->checksum = 0;

        std::memcpy(packet.data() + sizeof(struct icmphdr), payload.data(), payload.size());
        icmp->checksum = tunnel::IcmpUtils::calculate_checksum(packet);

        sendto(sockfd, packet.data(), packet.size(), 0, (struct sockaddr*)&dest_addr,
               sizeof(dest_addr));
        std::cout << "Пакет с командой отправлен. Ожидание результата..." << std::endl;

        std::vector<uint8_t> recv_buffer(65535);
        while (true) {
            ssize_t bytes = recv(sockfd, recv_buffer.data(), recv_buffer.size(), 0);

            if (bytes < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    throw tunnel::NetworkException(
                        "Таймаут: сервер не ответил в течение 5 секунд.");
                }
                throw tunnel::NetworkException("Не удалось прочитать данные из сокета.");
            }

            if (bytes > 0) {
                struct iphdr* ip = reinterpret_cast<struct iphdr*>(recv_buffer.data());
                int ip_hdr_len = ip->ihl * 4;
                struct icmphdr* icmp_reply =
                    reinterpret_cast<struct icmphdr*>(recv_buffer.data() + ip_hdr_len);

                if (icmp_reply->type == ICMP_ECHOREPLY) {
                    int data_offset = ip_hdr_len + sizeof(struct icmphdr);
                    std::vector<uint8_t> reply_payload(recv_buffer.begin() + data_offset,
                                                       recv_buffer.begin() + bytes);

                    std::string result = tunnel::IcmpUtils::extract_payload(
                        reply_payload, tunnel::IcmpUtils::MAGIC_RES);
                    if (!result.empty()) {
                        std::cout << "Ответ сервера:\n" << result;
                        break;
                    }
                }
            }
        }
        close(sockfd);
        sockfd = -1;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        if (sockfd >= 0) {
            close(sockfd);
        }
        return 1;
    }
    return 0;
}
