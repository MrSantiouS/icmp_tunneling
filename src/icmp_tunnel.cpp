#include "icmp_tunnel.hpp"

#include <arpa/inet.h>

#include <array>
#include <fstream>
#include <memory>

namespace tunnel {

NetworkException::NetworkException(const std::string& message) : std::runtime_error(message) {}

const std::string IcmpUtils::MAGIC_REQ = "TNRQ";
const std::string IcmpUtils::MAGIC_RES = "TNRS";
const std::string IcmpUtils::CRYPTO_KEY = "Xor-secret-key";

// НАЧАЛО ЗАИМСТВОВАНИЯ
uint16_t IcmpUtils::calculate_checksum(const std::vector<uint8_t>& data) {
    uint32_t sum = 0;
    size_t length = data.size();
    const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data.data());

    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }

    if (length == 1) {
        sum += *reinterpret_cast<const uint8_t*>(ptr);
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
}
// КОНЕЦ ЗАИМСТВОВАНИЯ

void IcmpUtils::xor_cipher(std::vector<uint8_t>& data, const std::string& key) {
    if (key.empty()) return;
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key[i % key.length()];
    }
}

std::vector<uint8_t> IcmpUtils::wrap_payload(const std::string& payload, const std::string& magic) {
    std::vector<uint8_t> encrypted_payload(payload.begin(), payload.end());
    xor_cipher(encrypted_payload, CRYPTO_KEY);
    std::vector<uint8_t> result(magic.begin(), magic.end());
    result.insert(result.end(), encrypted_payload.begin(), encrypted_payload.end());
    return result;
}

void IcmpUtils::validate_payload_size(size_t size) {
    const size_t MAX_SAFE_PAYLOAD = 1400;
    if (size > MAX_SAFE_PAYLOAD) {
        throw NetworkException("Размер полезной нагрузки (" + std::to_string(size) +
                               " байт) превышает безопасный MTU лимит (" +
                               std::to_string(MAX_SAFE_PAYLOAD) + " байт). " +
                               "Пакет будет отброшен.");
    }
}

std::string IcmpUtils::extract_payload(const std::vector<uint8_t>& raw_data,
                                       const std::string& magic) {
    if (raw_data.size() < magic.size()) return "";

    std::string signature(raw_data.begin(), raw_data.begin() + magic.size());
    if (signature != magic) return "";

    std::vector<uint8_t> encrypted_payload(raw_data.begin() + magic.size(), raw_data.end());
    xor_cipher(encrypted_payload, CRYPTO_KEY);

    return std::string(encrypted_payload.begin(), encrypted_payload.end());
}

bool IcmpUtils::is_valid_ipv4(const std::string& ip) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));
    return result != 0;
}

std::string IcmpUtils::execute_command(const std::string& command) {
    std::array<char, 128> buffer;
    std::string result;

    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) throw NetworkException("Не удалось открыть процесс через popen");

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    return result.empty() ? "Command executed (no output)" : result;
}

std::string IcmpUtils::read_from_file(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) throw NetworkException("Не удалось открыть файл: " + filepath);
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

}
