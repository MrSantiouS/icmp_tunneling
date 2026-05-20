#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace tunnel {

class NetworkException : public std::runtime_error {
   public:
    explicit NetworkException(const std::string& message);
};

class IcmpUtils {
   public:
    static const std::string MAGIC_REQ;

    static const std::string MAGIC_RES;

    static const std::string CRYPTO_KEY;

    static uint16_t calculate_checksum(const std::vector<uint8_t>& data);

    static void xor_cipher(std::vector<uint8_t>& data, const std::string& key);

    static std::vector<uint8_t> wrap_payload(const std::string& payload, const std::string& magic);

    static void validate_payload_size(size_t size);

    static std::string extract_payload(const std::vector<uint8_t>& raw_data,
                                       const std::string& magic);

    static bool is_valid_ipv4(const std::string& ip);

    static std::string execute_command(const std::string& command);

    static std::string read_from_file(const std::string& filepath);
};

}
