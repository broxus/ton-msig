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

inline auto now_ms() -> td::uint64
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

template <typename T, size_t N>
static auto load_slice(T (&data)[N]) -> td::Slice
{
    return td::Slice{reinterpret_cast<const char*>(data), N * sizeof(T)};
}

}  // namespace app
