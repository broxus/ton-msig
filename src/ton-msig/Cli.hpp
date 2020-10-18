#pragma once


#include <crypto/Ed25519.h>
#include <crypto/block/block.h>
#include <tdutils/td/utils/misc.h>

#include <CLI/CLI.hpp>
#include <any>
#include <typeindex>

namespace app
{
class CliState {
public:
    template <typename T, typename... Args>
    auto set(const std::string& name, Args&&... args) -> T&
    {
        const auto type_id = std::type_index{typeid(T)};
        auto map = parameters_.find(type_id);
        if (map == parameters_.end()) {
            auto [values, inserted] = parameters_.emplace(type_id, std::unordered_map<std::string, std::any>{});
            CHECK(inserted)
            map = values;
        }

        if (auto it = map->second.find(name); it != map->second.end()) {
            it->second = std::make_any<T>(std::forward<Args>(args)...);
            return *std::any_cast<T>(&it->second);
        }
        else {
            auto [value, inserted] = map->second.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(name),
                std::forward_as_tuple<const std::in_place_type_t<T>&, Args&&...>(std::in_place_type<T>, std::forward<Args>(args)...));
            CHECK(inserted)

            return *std::any_cast<T>(&value->second);
        }
    }

    template <typename T>
    auto get(const std::string& name) -> T&
    {
        constexpr auto error_message = "parameter not found";
        const auto type_id = std::type_index{typeid(T)};

        auto map = parameters_.find(type_id);
        if (map == parameters_.end()) {
            throw std::runtime_error{error_message};
        }

        if (auto it = map->second.find(name); it != map->second.end()) {
            return *std::any_cast<T>(&it->second);
        }
        else {
            throw std::runtime_error{error_message};
        }
    }

private:
    std::unordered_map<std::type_index, std::unordered_map<std::string, std::any>> parameters_;
};

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

struct KeyValidator : public CLI::Validator {
    KeyValidator();
    constexpr static auto type_name = "KEY";
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
