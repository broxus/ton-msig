#pragma once

#include <crypto/Ed25519.h>
#include <crypto/block/block.h>
#include <tdutils/td/utils/misc.h>

#include <CLI/CLI.hpp>

namespace app
{
struct MnemonicsValidator : public CLI::Validator {
    MnemonicsValidator();
    constexpr static auto type_name = "MNEMONICS";
};

struct AddressValidator : public CLI::Validator {
    AddressValidator();
    constexpr static auto type_name = "ADDRESS";
};

struct TonValidator : public CLI::Validator {
    TonValidator();
    constexpr static auto type_name = "TON";
};

struct PubKeyValidator : public CLI::Validator {
    PubKeyValidator();
    constexpr static auto type_name = "PUBKEY";
};

struct HexValidator : public CLI::Validator {
    explicit HexValidator(size_t length = 64u);
    constexpr static auto type_name = "HEX";
};

auto is_mnemonics(const std::string& str) -> bool;
auto is_hex_string(const std::string& str, size_t length) -> bool;

template <typename T = int>
auto check_result(td::Result<T>&& result, const std::string& prefix = "") -> T
{
    if (result.is_error()) {
        std::cerr << result.move_as_error_prefix(prefix).message().c_str() << std::endl;
        std::exit(1);
    }
    return result.move_as_ok();
}

auto load_key(const std::string& str) -> td::Result<td::Ed25519::PrivateKey>;

struct MessageInfo {
    td::Bits256 hash{};
    td::uint64 created_at{0};
    td::uint32 expires_at{std::numeric_limits<td::uint32>::max()};
};
auto load_message_info(const std::string& str) -> td::Result<MessageInfo>;

}  // namespace app
