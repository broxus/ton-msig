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

auto is_mnemonics(const std::string& str) -> bool;

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

}  // namespace app
