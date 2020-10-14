#include "Cli.hpp"

#include <td/utils/JsonBuilder.h>
#include <td/utils/misc.h>
#include <tdutils/td/utils/filesystem.h>
#include <tonlib/keys/Mnemonic.h>

#include <keys/keys.hpp>

namespace app
{
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
        constexpr auto prefix_length = 2u;  // "0x"
        constexpr auto key_length = 64u;
        constexpr auto error_prefix = "Invalid public key value: ";

        const char* start;
        if (const auto size = str.size(); size == key_length) {
            start = str.c_str();
        }
        else if (size == key_length + prefix_length && str[0] == '0' && str[1] == 'x') {
            start = str.c_str() + prefix_length;
        }
        else {
            return error_prefix + str;
        }

        for (size_t i = 0; i < key_length; ++i) {
            const auto c = start[i];

            if (!td::is_hex_digit(c)) {
                return error_prefix + str;
            }
        }

        auto decoded_r = td::hex_decode(td::Slice{start});
        if (decoded_r.is_error()) {
            return error_prefix + str;
        }
        str = decoded_r.move_as_ok();

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

auto load_key(const std::string& str) -> td::Result<td::Ed25519::PrivateKey>
{
    if (is_mnemonics(str)) {
        TRY_RESULT(mnemonic, tonlib::Mnemonic::create(td::SecureString{str}, {}))
        return mnemonic.to_private_key();
    }
    else {
        TRY_RESULT(keys_file, td::read_file(str))
        TRY_RESULT(json, td::json_decode(keys_file.as_slice()))
        auto& root = json.get_object();
        TRY_RESULT(secret, td::get_json_object_string_field(root, "secret", false))

        td::Bits256 private_key_data{};
        if (private_key_data.from_hex(secret) <= 0) {
            return td::Status::Error("Invalid secret");
        }

        return ton::privkeys::Ed25519{private_key_data.as_slice()}.export_key();
    }
}
}  // namespace app
