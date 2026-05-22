#include <gtest/gtest.h>

#include <fstream>

#include "icmp_tunnel.hpp"

TEST(IcmpUtilsTest, PayloadWrapAndExtractSuccess) {
    std::string test_cmd = "whoami";
    auto wrapped = tunnel::IcmpUtils::wrap_payload(test_cmd, tunnel::IcmpUtils::MAGIC_REQ);
    EXPECT_EQ(wrapped.size(), test_cmd.size() + tunnel::IcmpUtils::MAGIC_REQ.size());

    std::string extracted =
        tunnel::IcmpUtils::extract_payload(wrapped, tunnel::IcmpUtils::MAGIC_REQ);
    EXPECT_EQ(extracted, test_cmd);
}

TEST(IcmpUtilsTest, ExtractInvalidSignature) {
    std::vector<uint8_t> bad_data = {'F', 'A', 'K', 'E', 'd', 'a', 't', 'a'};
    std::string extracted =
        tunnel::IcmpUtils::extract_payload(bad_data, tunnel::IcmpUtils::MAGIC_REQ);
    EXPECT_TRUE(extracted.empty());
}

TEST(IcmpUtilsTest, ExtractTooShort) {
    std::vector<uint8_t> short_data = {'T', 'U'};
    std::string extracted =
        tunnel::IcmpUtils::extract_payload(short_data, tunnel::IcmpUtils::MAGIC_REQ);
    EXPECT_TRUE(extracted.empty());
}

TEST(IcmpUtilsTest, ChecksumCalculation) {
    std::vector<uint8_t> data = {0x08, 0x00, 0x00, 0x00, 0x00, 0x01,
                                 0x00, 0x01, 'T',  'E',  'S',  'T'};
    uint16_t checksum = tunnel::IcmpUtils::calculate_checksum(data);
    EXPECT_NE(checksum, 0);
}

TEST(IcmpUtilsTest, ExecuteCommand) {
    std::string result = tunnel::IcmpUtils::execute_command("echo hello");
    EXPECT_EQ(result, "hello\n");
}

TEST(IcmpUtilsTest, ReadFromFileNegative) {
    EXPECT_THROW(
        { tunnel::IcmpUtils::read_from_file("non_existent_file.txt"); }, tunnel::NetworkException);
}

TEST(IcmpUtilsTest, XorCipherEncryptionDecryption) {
    std::string original_text = "Super secret command payload!";
    std::vector<uint8_t> data(original_text.begin(), original_text.end());
    std::string key = "test_key";

    tunnel::IcmpUtils::xor_cipher(data, key);
    std::string encrypted_str(data.begin(), data.end());

    EXPECT_NE(encrypted_str, original_text);

    tunnel::IcmpUtils::xor_cipher(data, key);
    std::string decrypted_str(data.begin(), data.end());

    EXPECT_EQ(decrypted_str, original_text);
}

TEST(IcmpUtilsTest, WrapAndExtractEmptyPayload) {
    std::string empty_cmd = "";
    auto wrapped = tunnel::IcmpUtils::wrap_payload(empty_cmd, tunnel::IcmpUtils::MAGIC_RES);
    EXPECT_EQ(wrapped.size(), tunnel::IcmpUtils::MAGIC_RES.size());
    std::string extracted =
        tunnel::IcmpUtils::extract_payload(wrapped, tunnel::IcmpUtils::MAGIC_RES);
    EXPECT_EQ(extracted, "");
}

TEST(IcmpUtilsTest, ExtractSignatureNotAtBeginning) {
    std::string malformed_data = "JUNK_DATA_" + tunnel::IcmpUtils::MAGIC_REQ + "whoami";
    std::vector<uint8_t> raw_data(malformed_data.begin(), malformed_data.end());
    std::string extracted =
        tunnel::IcmpUtils::extract_payload(raw_data, tunnel::IcmpUtils::MAGIC_REQ);
    EXPECT_TRUE(extracted.empty());
}

TEST(IcmpUtilsTest, ChecksumOddLength) {
    std::vector<uint8_t> data_even = {0x0A, 0x0B, 0x0C, 0x0D};
    std::vector<uint8_t> data_odd = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E};
    uint16_t checksum_even = tunnel::IcmpUtils::calculate_checksum(data_even);
    uint16_t checksum_odd = tunnel::IcmpUtils::calculate_checksum(data_odd);
    EXPECT_NE(checksum_even, checksum_odd);
    EXPECT_NE(checksum_odd, 0);
}

TEST(IcmpUtilsTest, ExecuteNonExistentCommand) {
    std::string result = tunnel::IcmpUtils::execute_command("this_command_does_not_exist");
    EXPECT_EQ(result, "Command executed (no output)");
}

TEST(IcmpUtilsTest, ExtractExactSignatureNoData) {
    std::vector<uint8_t> signature_only(tunnel::IcmpUtils::MAGIC_REQ.begin(),
                                        tunnel::IcmpUtils::MAGIC_REQ.end());
    std::string extracted =
        tunnel::IcmpUtils::extract_payload(signature_only, tunnel::IcmpUtils::MAGIC_REQ);
    EXPECT_EQ(extracted, "");
}

TEST(IcmpUtilsTest, ReadFromFilePositive) {
    std::string test_file = "temp_test.txt";
    std::string test_data = "ls -la";

    std::ofstream out(test_file);
    out << test_data;
    out.close();

    std::string result = tunnel::IcmpUtils::read_from_file(test_file);
    EXPECT_EQ(result, test_data);

    std::remove(test_file.c_str());
}

TEST(IcmpUtilsTest, IPv4Validation) {
    EXPECT_TRUE(tunnel::IcmpUtils::is_valid_ipv4("127.0.0.1"));
    EXPECT_TRUE(tunnel::IcmpUtils::is_valid_ipv4("192.168.1.1"));
    EXPECT_FALSE(tunnel::IcmpUtils::is_valid_ipv4("999.999.999.999"));
    EXPECT_FALSE(tunnel::IcmpUtils::is_valid_ipv4("not_an_ip"));
}
