#pragma once

#include <tonlib/Stuff.h>

#include <ftabi/Abi.hpp>
#include <nlohmann/json.hpp>

namespace app
{
using EncodedMessage = std::tuple<ftabi::FunctionRef, td::Ref<vm::Cell>, td::Ref<vm::Cell>>;

struct ActionBase {
    virtual ~ActionBase() = default;

    virtual auto create_message() -> td::Result<EncodedMessage> = 0;
    virtual auto handle_prepared(const td::Ref<vm::Cell>& message) -> td::Status { return td::Status::OK(); };
    virtual auto handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status = 0;
    virtual void handle_error(td::Status error) = 0;

    [[nodiscard]] virtual auto created_at() const -> td::uint64 { return 0u; }
    [[nodiscard]] virtual auto expires_at() const -> td::uint32 { return std::numeric_limits<td::uint32>::max(); }
    [[nodiscard]] virtual auto is_get_method() const -> bool = 0;

    template <typename T>
    auto as() -> T&
    {
        static_assert(std::is_base_of_v<ActionBase, T>);
        return *dynamic_cast<T*>(this);
    }

    template <typename T>
    auto as() const -> const T&
    {
        static_assert(std::is_base_of_v<ActionBase, T>);
        return *dynamic_cast<const T*>(this);
    }
};

template <typename R>
struct Action : ActionBase {
    using Result = R;
    using Handler = td::Promise<R>;

    explicit Action(td::Promise<R>&& promise)
        : promise(std::move(promise)){};

    void handle_error(td::Status error) final { promise.set_error(error.move_as_error()); }

    td::Promise<R> promise;
};

template <typename T>
auto check_output(const std::vector<ftabi::ValueRef>& output) -> td::Status
{
    constexpr td::Slice INVALID_OUTPUT = "invalid output";

    if constexpr (std::is_same_v<decltype(T::output_type()), std::vector<ftabi::ParamRef>>) {
        auto params = T::output_type();
        if (output.size() != params.size()) {
            return td::Status::Error(INVALID_OUTPUT);
        }
        for (size_t i = 0; i < params.size(); ++i) {
            if (!output[i]->check_type(params[i])) {
                return td::Status::Error(INVALID_OUTPUT);
            }
        }
    }
    else {
        if (output.size() != 1 || !output[0]->check_type(T::output_type())) {
            return td::Status::Error("invalid output");
        }
    }

    return td::Status::OK();
}

auto empty_function_call() -> ftabi::FunctionCallRef;

}  // namespace app
