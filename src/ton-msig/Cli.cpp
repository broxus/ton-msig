#include "Cli.hpp"

#include <td/utils/JsonBuilder.h>
#include <td/utils/misc.h>
#include <tdutils/td/utils/filesystem.h>
#include <tonlib/keys/Mnemonic.h>

#include <keys/keys.hpp>

namespace app
{
namespace
{
auto without_prefix(const std::string& str) -> td::Slice
{
    const auto prefix_offset = ((str[1] == 'x') << 1u);
    return td::Slice{str.c_str() + prefix_offset, str.size() - prefix_offset};
}

}  // namespace

MnemonicsValidator::MnemonicsValidator()
    : CLI::Validator(type_name)
{
    func_ = [](const std::string& str) {
        if (!is_mnemonics(str)) {
            return "Invalid signature words: " + str;
        }
        return std::string{};
    };
}

AddressValidator::AddressValidator()
    : CLI::Validator(type_name)
{
    func_ = [](const std::string& str) {
        if (!block::StdAddress{}.parse_addr(str)) {
            return "Invalid contract address: " + str;
        }
        return std::string{};
    };
}

TonValidator::TonValidator()
    : CLI::Validator(type_name)
{
    func_ = [](std::string& str) -> std::string {
        constexpr auto error_prefix = "Invalid TON value: ";

        if (str.empty()) {
            return error_prefix;
        }

        bool is_nano = str[0] == 'T', is_valid = true, has_digit = false, has_dot = false;
        auto dot_pos = std::string::npos;
        size_t decimals = 0;

        for (size_t i = is_nano; i < str.size(); ++i) {
            const auto c = str[i];

            const auto is_dot = c == '.' || c == ',';
            const auto is_digit = td::is_digit(c);

            if (!is_nano && is_dot || is_dot && (has_dot || !has_digit) || !is_dot && (!is_digit || has_dot && ++decimals > 9)) {
                is_valid = false;
                break;
            }

            if (is_dot) {
                has_dot = true;
                dot_pos = i;
            }

            if (is_digit) {
                has_digit = true;
            }
        }

        if (!is_valid || (str.size() - is_nano) == 0) {
            return error_prefix + str;
        }

        if (dot_pos != std::string::npos) {
            str.erase(dot_pos, 1);
        }
        if (is_nano) {
            str.erase(0, 1);
            str += std::string(9u - decimals, '0');
        }

        return std::string{};
    };
}

PubKeyValidator::PubKeyValidator()
    : CLI::Validator(type_name)
{
    func_ = [](std::string& str) -> std::string {
        constexpr auto key_length = 64u;
        constexpr auto error_prefix = "Invalid public key value: ";

        if (!is_hex_string(str, key_length)) {
            return error_prefix + str;
        }

        auto decoded_r = td::hex_decode(without_prefix(str));
        if (decoded_r.is_error()) {
            return error_prefix + str;
        }
        str = decoded_r.move_as_ok();

        return std::string{};
    };
}

HexValidator::HexValidator(size_t length)
    : CLI::Validator(type_name)
{
    func_ = [length](std::string& str) -> std::string {
        constexpr auto error_prefix = "Invalid hex value: ";

        if (!is_hex_string(str, length)) {
            return error_prefix + str;
        }

        if (str[1] == 'x') {
            str.erase(0, 2);
        }

        return std::string{};
    };
}

auto is_mnemonics(const std::string& str) -> bool
{
    size_t word_count = 1;
    for (size_t i = 0; i < str.size(); ++i) {
        const auto c = str[i];

        const auto after_space = i != 0 && str[i - 1] == ' ';
        const auto is_space = c == ' ';

        if (is_space && after_space || !is_space && (!td::is_alpha(c) || !std::islower(c))) {
            return false;
        }
        else if (is_space) {
            ++word_count;
        }
    }
    return word_count == 12;
}

auto is_hex_string(const std::string& str, size_t length) -> bool
{
    constexpr auto prefix_length = 2u;  // "0x"

    const char* start;
    if (const auto size = str.size(); size == length) {
        start = str.c_str();
    }
    else if (size == length + prefix_length && str[0] == '0' && str[1] == 'x') {
        start = str.c_str() + prefix_length;
    }
    else {
        return false;
    }

    for (size_t i = 0; i < length; ++i) {
        if (!td::is_hex_digit(start[i])) {
            return false;
        }
    }

    return true;
}

auto load_key(const std::string& str) -> td::Result<td::Ed25519::PrivateKey>
{
    auto file_r = td::read_file(str);

    if (file_r.is_ok()) {
        auto keys_file = file_r.move_as_ok();
        TRY_RESULT(json, td::json_decode(keys_file.as_slice()))
        auto& root = json.get_object();
        TRY_RESULT(secret, td::get_json_object_string_field(root, "secret", false))

        td::Bits256 private_key_data{};
        if (private_key_data.from_hex(secret) <= 0) {
            return td::Status::Error("Invalid secret");
        }

        return ton::privkeys::Ed25519{private_key_data.as_slice()}.export_key();
    }
    else if (is_mnemonics(str)) {
        TRY_RESULT(mnemonic, tonlib::Mnemonic::create(td::SecureString{str}, {}))
        return mnemonic.to_private_key();
    }
    else {
        return file_r.move_as_error();
    }
}

auto parse_hash(td::Slice data) -> td::Result<td::Bits256>
{
    td::Bits256 hash_data{};
    if (hash_data.from_hex(data) <= 0) {
        return td::Status::Error("Invalid message hash");
    }

    return hash_data;
}

auto load_message_info(const std::string& str) -> td::Result<MessageInfo>
{
    auto fie_r = td::read_file(str);

    if (fie_r.is_ok()) {
        auto msg_info_file = fie_r.move_as_ok();
        TRY_RESULT(json, td::json_decode(msg_info_file.as_slice()))
        auto& root = json.get_object();

        MessageInfo info;
        for (const auto& [key, value] : root) {
            if (key == "message_hash") {
                if (value.type() != td::JsonValue::Type::String) {
                    return td::Status::Error("expected message_hash as string");
                }
                auto& hash = info.hash;
                TRY_RESULT_ASSIGN(hash, parse_hash(value.get_string()))
            }
            else if (key == "created_at") {
                if (value.type() != td::JsonValue::Type::Number) {
                    return td::Status::Error("expected created_at as number");
                }
                auto& created_at = info.created_at;
                TRY_RESULT_ASSIGN(created_at, td::to_integer_safe<td::uint64>(value.get_number()))
            }
            else if (key == "expires_at") {
                if (value.type() != td::JsonValue::Type::Number) {
                    return td::Status::Error("expected expires_at as number");
                }
                auto& expires_at = info.expires_at;
                TRY_RESULT_ASSIGN(expires_at, td::to_integer_safe<td::uint32>(value.get_number()))
            }
        }
        return info;
    }
    else if (is_hex_string(str, 64u)) {
        MessageInfo info;
        auto& hash = info.hash;
        TRY_RESULT_ASSIGN(hash, parse_hash(without_prefix(str)))

        return info;
    }
    else {
        return fie_r.move_as_error();
    }
}

}  // namespace app
