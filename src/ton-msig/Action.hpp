#pragma once

#include <tonlib/Stuff.h>

#include <ftabi/Abi.hpp>

namespace app
{
using EncodedBody = std::pair<ftabi::FunctionRef, td::Ref<vm::Cell>>;

struct ActionBase {
    virtual auto create_body() -> td::Result<EncodedBody> = 0;
    virtual auto handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status = 0;
};

template <int id_, typename R>
struct Action : ActionBase {
    using Result = R;
    using Handler = td::Promise<R>;

    constexpr static auto id = id_;

    explicit Action(td::Promise<R>&& promise)
        : promise(std::move(promise)){};

    td::Promise<R> promise;
};

namespace msig
{
struct Parameters {
    td::uint8 max_queued_transactions{};
    td::uint8 max_custodian_count{};
    td::uint64 expiration_time{};
    td::BigInt256 min_value{};
    td::uint8 required_txn_confirms{};
};

struct Transaction {
    td::uint64 id{};
    td::uint32 confirmationMask{};
    td::uint8 signsRequired{};
    td::uint8 signsReceived{};
    td::BigInt256 creator{};
    td::uint8 index{};
    block::StdAddress dest{};
    td::BigInt256 value{};
    td::uint16 send_flags{};
    bool bounce{};
};

struct Custodian {
    td::uint8 index{};
    td::BigInt256 pubkey{};
};

enum { submit_transaction, confirm_transaction, is_confirmed, get_parameters, get_transaction, get_transaction_ids, get_transactions, get_custodians };

struct IsConfirmed final : Action<is_confirmed, bool> {
    explicit IsConfirmed(Handler&& promise);

    auto create_body() -> td::Result<EncodedBody> final;
    auto handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status final;
};

struct GetParameters final : Action<get_parameters, Parameters> {
    explicit GetParameters(Handler&& promise);

    static auto output_type() -> std::vector<ftabi::ParamRef>;
    auto create_body() -> td::Result<EncodedBody> final;
    auto handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status final;
};

struct GetTransaction final : Action<get_transaction, Transaction> {
    explicit GetTransaction(Handler&& promise, td::uint64 transaction_id);

    static auto output_type() -> ftabi::ParamRef;
    auto create_body() -> td::Result<EncodedBody> final;
    auto handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status final;

    td::uint64 transaction_id_;
};

struct GetTransactions final : Action<get_transactions, std::vector<Transaction>> {
    explicit GetTransactions(Handler&& promise);

    static auto output_type() -> ftabi::ParamRef;
    auto create_body() -> td::Result<EncodedBody> final;
    auto handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status final;
};

struct GetTransactionIds final : Action<get_transaction_ids, std::vector<td::uint64>> {
    explicit GetTransactionIds(Handler&& promise);

    static auto output_type() -> ftabi::ParamRef;
    auto create_body() -> td::Result<EncodedBody> final;
    auto handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status final;
};

struct GetCustodians final : Action<get_custodians, std::vector<Custodian>> {
    explicit GetCustodians(Handler&& promise);

    static auto output_type() -> ftabi::ParamRef;
    auto create_body() -> td::Result<EncodedBody> final;
    auto handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status final;
};

}  // namespace msig

}  // namespace app
