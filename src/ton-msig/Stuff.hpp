#pragma once

#include <cassert>
#include <variant>

namespace app
{
enum class AccountStatus {
    empty,
    uninit,
    frozen,
    active,
    unknown,
};

constexpr auto to_string(AccountStatus account_status) -> const char*
{
    switch (account_status) {
        case AccountStatus::empty:
            return "unknown";
        case AccountStatus::uninit:
            return "account_uninit";
        case AccountStatus::frozen:
            return "account_frozen";
        case AccountStatus::active:
            return "account_active";
        default:
            return "unknown";
    }
}

template<typename>
struct is_std_vector : std::false_type {};
template<typename T, typename A>
struct is_std_vector<std::vector<T,A>> : std::true_type {};

template <typename Type, typename... Types>
[[nodiscard]] inline Type& get(std::variant<Types...>& value)
{
    const auto result = std::get_if<Type>(&value);
    assert(result != 0);
    return *result;
}

}  // namespace app
