#pragma once

#include <td/actor/actor.h>

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

template <typename>
struct is_std_vector : std::false_type {
};
template <typename T, typename A>
struct is_std_vector<std::vector<T, A>> : std::true_type {
};

template <typename T>
auto move_copy(const T& value) -> T
{
    return value;
}

}  // namespace app
