#include "Action.hpp"

#include <td/utils/base64.h>
#include <td/utils/filesystem.h>

#include <utility>

#include "Contract.hpp"
#include "Stuff.hpp"

using namespace ftabi;

namespace app::msig
{
namespace
{
auto make_header_params() -> HeaderParams
{
    return make_params(ParamPublicKey{}, ParamTime{}, ParamExpire{});
}

auto empty_function_call() -> FunctionCallRef
{
    static FunctionCallRef call{FunctionCall{{}}};
    return call;
}

template <typename T>
auto check_output(const std::vector<ftabi::ValueRef>& output) -> td::Status
{
    constexpr td::Slice INVALID_OUTPUT = "invalid output";

    if constexpr (std::is_same_v<decltype(T::output_type()), std::vector<ParamRef>>) {
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

auto transaction_param() -> ParamTuple
{
    return ParamTuple{
        "transaction",
        ParamUint{"id", 64},
        ParamUint{"confirmationsMask", 32},
        ParamUint{"signsRequired", 8},
        ParamUint{"signsReceived", 8},
        ParamUint{"creator", 256},
        ParamUint{"index", 8},
        ParamAddress{"dest"},
        ParamUint{"value", 128},
        ParamUint{"sendFlags", 16},
        ParamCell{"payload"},
        ParamBool{"bounce"},
    };
}

auto save_message_info(const std::optional<std::string>& path, td::uint64 created_at, td::uint32 expires_at, const td::Ref<vm::Cell>& message) -> td::Status
{
    if (!path.has_value()) {
        return td::Status::OK();
    }

    TRY_RESULT(encoded, vm::std_boc_serialize(message))

    const auto data = PSLICE() << "{\n"
                               << R"(  "created_at": )" << created_at << ",\n"
                               << R"(  "expires_at": )" << expires_at << ",\n"
                               << R"(  "message": ")" << td::base64_encode(encoded.as_slice()) << "\",\n"
                               << R"(  "message_hash": ")" << message->get_hash().to_hex() << "\"\n"
                               << "}\n";

    return td::atomic_write_file(*path, data);
}

auto decode_parameters(const std::vector<ValueRef>& values) -> Parameters
{
    return Parameters{
        .max_queued_transactions = values[0]->as<ValueInt>().get<td::uint8>(),
        .max_custodian_count = values[1]->as<ValueInt>().get<td::uint8>(),
        .expiration_time = values[2]->as<ValueInt>().get<td::uint64>(),
        .min_value = values[3]->as<ValueInt>().value,
        .required_txn_confirms = values[4]->as<ValueInt>().get<td::uint8>(),
    };
}

auto decode_transaction(const ValueRef& value) -> Transaction
{
    const auto& t = value->as<ValueTuple>();
    return Transaction{
        .id = t.values[0]->as<ValueInt>().get<td::uint64>(),
        .confirmationMask = t.values[1]->as<ValueInt>().get<td::uint32>(),
        .signsRequired = t.values[2]->as<ValueInt>().get<td::uint8>(),
        .signsReceived = t.values[3]->as<ValueInt>().get<td::uint8>(),
        .creator = t.values[4]->as<ValueInt>().value,
        .index = t.values[5]->as<ValueInt>().get<td::uint8>(),
        .dest = t.values[6]->as<ValueAddress>().value,
        .value = t.values[7]->as<ValueInt>().value,
        .send_flags = t.values[8]->as<ValueInt>().get<td::uint16>(),
        // skip: t.values[9]->as<ValueCell>().value
        .bounce = t.values[10]->as<ValueBool>().value};
}

auto decode_custodian(const ValueRef& value) -> Custodian
{
    const auto& t = value->as<ValueTuple>();
    return Custodian{
        .index = t.values[0]->as<ValueInt>().get<td::uint8>(),
        .pubkey = t.values[1]->as<ValueInt>().value,
    };
}

}  // namespace

// constructor

Constructor::Constructor(
    Handler&& promise,
    bool force_local,
    td::uint64 time,
    td::uint32 expire,
    std::vector<td::BigInt256>&& owners,
    td::uint8 req_confirms,
    const td::Ed25519::PrivateKey& private_key,
    std::optional<std::string> msg_info_path)
    : Action{std::move(promise)}
    , force_local_{force_local}
    , time_{time}
    , expire_{expire}
    , owners_{std::move(owners)}
    , req_confirms_{req_confirms}
    , private_key_{private_key.as_octet_string().copy()}
    , msg_info_path_{std::move(msg_info_path)}
{
}

auto Constructor::create_message() -> td::Result<EncodedMessage>
{
    static auto input_params = make_params(ParamArray{"owners", ParamUint{"owner", 256}}, ParamUint{"reqConfirms", 8});
    static auto function = td::Ref{Function{"constructor", make_header_params(), move_copy(input_params), {output_type()}}};

    TRY_RESULT(public_key, private_key_.get_public_key())

    std::vector<ValueRef> owners;
    owners.reserve(owners_.size());
    for (const auto& owner : owners_) {
        owners.emplace_back(make_value(ParamUint{"owner", 256}, owner));
    }

    HeaderValues header_values =
        make_header(make_value(ParamPublicKey{}, public_key.as_octet_string()), make_value(ParamTime{}, time_), make_value(ParamExpire{}, expire_));
    InputValues input_values{
        make_value<ValueArray>(input_params[0], std::move(owners)),  //
        make_value<ValueInt>(input_params[1], td::make_bigint(req_confirms_))};

    FunctionCallRef call{FunctionCall{std::move(header_values), std::move(input_values), false, private_key_.as_octet_string().copy()}};

    TRY_RESULT(init_state, Contract::generate_state_init(public_key))
    TRY_RESULT(body, function->encode_input(call))

    return std::make_tuple(function, std::move(init_state), std::move(body));
}

auto Constructor::handle_prepared(const td::Ref<vm::Cell>& message) -> td::Status
{
    return save_message_info(msg_info_path_, time_, expire_, message);
}

auto Constructor::handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status
{
    TRY_STATUS(check_output<ConfirmTransaction>(result))
    promise.set_result(std::nullopt);
    return td::Status::OK();
}

// submit_transaction

SubmitTransaction::SubmitTransaction(
    Action::Handler&& promise,
    bool force_local,
    td::uint64 time,
    td::uint32 expire,
    const block::StdAddress& dest,
    const td::BigInt256& value,
    bool bounce,
    bool all_balance,
    td::Ref<vm::Cell> payload,
    const td::Ed25519::PrivateKey& private_key,
    std::optional<std::string> msg_info_path)
    : Action{std::move(promise)}
    , force_local_{force_local}
    , time_{time}
    , expire_{expire}
    , dest_{dest}
    , value_{value}
    , bounce_{bounce}
    , all_balance_{all_balance}
    , payload_{std::move(payload)}
    , private_key_{private_key.as_octet_string().copy()}
    , msg_info_path_{std::move(msg_info_path)}
{
}

auto SubmitTransaction::output_type() -> ftabi::ParamRef
{
    static ParamRef param{ParamUint{"transId", 64}};
    return param;
}

auto SubmitTransaction::create_message() -> td::Result<EncodedMessage>
{
    static auto input_params = make_params(ParamAddress{"dest"}, ParamUint{"value", 128}, ParamBool{"bounce"}, ParamBool{"allBalance"}, ParamCell{"payload"});
    static auto function = td::Ref{Function{"submitTransaction", make_header_params(), move_copy(input_params), {output_type()}}};

    TRY_RESULT(public_key, private_key_.get_public_key())

    HeaderValues header_values =
        make_header(make_value(ParamPublicKey{}, public_key.as_octet_string()), make_value(ParamTime{}, time_), make_value(ParamExpire{}, expire_));
    InputValues input_values{
        make_value<ValueAddress>(input_params[0], dest_),
        make_value<ValueInt>(input_params[1], value_),
        make_value<ValueBool>(input_params[2], bounce_),
        make_value<ValueBool>(input_params[3], all_balance_),
        make_value<ValueCell>(input_params[4], payload_)};

    FunctionCallRef call{FunctionCall{std::move(header_values), std::move(input_values), false, private_key_.as_octet_string().copy()}};

    TRY_RESULT(body, function->encode_input(call))
    return std::make_tuple(function, td::Ref<vm::Cell>{}, std::move(body));
}

auto SubmitTransaction::handle_prepared(const td::Ref<vm::Cell>& message) -> td::Status
{
    return save_message_info(msg_info_path_, time_, expire_, message);
}

auto SubmitTransaction::handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status
{
    TRY_STATUS(check_output<SubmitTransaction>(result))
    promise.set_result(result[0]->as<ValueInt>().get<td::uint64>());
    return td::Status::OK();
}

// confirm_transaction

ConfirmTransaction::ConfirmTransaction(
    Action::Handler&& promise,
    bool force_local,
    td::uint64 time,
    td::uint32 expire,
    td::uint64 transaction_id,
    const td::Ed25519::PrivateKey& private_key,
    std::optional<std::string> msg_info_path)
    : Action{std::move(promise)}
    , force_local_{force_local}
    , time_{time}
    , expire_{expire}
    , transaction_id_{transaction_id}
    , private_key_{private_key.as_octet_string().copy()}
    , msg_info_path_{std::move(msg_info_path)}
{
}

auto ConfirmTransaction::create_message() -> td::Result<EncodedMessage>
{
    static ParamRef input_param{ParamUint{"transactionId", 64}};
    static auto function = td::Ref{Function{"confirmTransaction", make_header_params(), {input_param}, {output_type()}}};

    TRY_RESULT(public_key, private_key_.get_public_key())

    HeaderValues header_values =
        make_header(make_value(ParamPublicKey{}, public_key.as_octet_string()), make_value(ParamTime{}, time_), make_value(ParamExpire{}, expire_));
    InputValues input_values{make_value<ValueInt>(input_param, td::make_bigint(transaction_id_))};

    FunctionCallRef call{FunctionCall{std::move(header_values), std::move(input_values), false, private_key_.as_octet_string().copy()}};

    TRY_RESULT(body, function->encode_input(call))
    return std::make_tuple(function, td::Ref<vm::Cell>{}, std::move(body));
}

auto ConfirmTransaction::handle_prepared(const td::Ref<vm::Cell>& message) -> td::Status
{
    return save_message_info(msg_info_path_, time_, expire_, message);
}

auto ConfirmTransaction::handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status
{
    TRY_STATUS(check_output<ConfirmTransaction>(result))
    promise.set_result(std::nullopt);
    return td::Status::OK();
}

// is_confirmed

IsConfirmed::IsConfirmed(Action::Handler&& promise, td::uint32 mask, td::uint8 index)
    : Action{std::move(promise)}
    , mask_{mask}
    , index_{index}
{
}

auto IsConfirmed::output_type() -> ftabi::ParamRef
{
    static ParamRef param{ParamBool{"confirmed"}};
    return param;
}

auto IsConfirmed::create_message() -> td::Result<EncodedMessage>
{
    static auto input_params = make_params(ParamUint{"mask", 32}, ParamUint{"index", 8});
    static auto function = td::Ref{Function{"isConfirmed", make_header_params(), move_copy(input_params), {output_type()}}};

    FunctionCallRef call{FunctionCall{
        {make_value<ValueInt>(input_params[0], td::make_bigint(mask_)),  //
         make_value<ValueInt>(input_params[1], td::make_bigint(index_))}}};

    TRY_RESULT(body, function->encode_input(call))
    return std::make_tuple(function, td::Ref<vm::Cell>{}, std::move(body));
}

auto IsConfirmed::handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status
{
    TRY_STATUS(check_output<IsConfirmed>(result))
    promise.set_result(result[0]->as<ValueBool>().value);
    return td::Status::OK();
}

// get_parameters

GetParameters::GetParameters(Action::Handler&& promise)
    : Action{std::move(promise)}
{
}

auto GetParameters::output_type() -> std::vector<ftabi::ParamRef>
{
    static std::vector<ParamRef> params = make_params(
        ParamUint{"maxQueuedTransactions", 8},
        ParamUint{"maxCustodianCount", 8},
        ParamUint{"expirationTime", 64},
        ParamUint{"minValue", 128},
        ParamUint{"requiredTxnConfirms", 8});
    return params;
}

auto GetParameters::create_message() -> td::Result<EncodedMessage>
{
    static auto function = td::Ref{Function{"getParameters", make_header_params(), {}, {output_type()}}};
    TRY_RESULT(body, function->encode_input(empty_function_call()))
    return std::make_tuple(function, td::Ref<vm::Cell>{}, std::move(body));
}

auto GetParameters::handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status
{
    TRY_STATUS(check_output<GetParameters>(result))
    promise.set_result(decode_parameters(result));
    return td::Status::OK();
}

// get_transaction

GetTransaction::GetTransaction(Action::Handler&& promise, td::uint64 transaction_id)
    : Action{std::move(promise)}
    , transaction_id_{transaction_id}
{
}

auto GetTransaction::output_type() -> ftabi::ParamRef
{
    static ParamRef param{transaction_param()};
    return param;
}

auto GetTransaction::create_message() -> td::Result<EncodedMessage>
{
    static auto function = td::Ref{Function{"getTransaction", make_header_params(), make_params(ParamUint{"id", 64}), {output_type()}}};

    auto call = FunctionCallRef{FunctionCall{{make_value(ParamUint{"id", 64}, td::make_bigint(transaction_id_))}}};

    TRY_RESULT(body, function->encode_input(call))
    return std::make_tuple(function, td::Ref<vm::Cell>{}, std::move(body));
}

auto GetTransaction::handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status
{
    TRY_STATUS(check_output<GetTransaction>(result))
    promise.set_result(decode_transaction(result[0]));
    return td::Status::OK();
}

// get_transactions

GetTransactions::GetTransactions(Action::Handler&& promise)
    : Action{std::move(promise)}
{
}

auto GetTransactions::output_type() -> ftabi::ParamRef
{
    static ParamRef param{ParamArray{"transactions", transaction_param()}};
    return param;
}

auto GetTransactions::create_message() -> td::Result<EncodedMessage>
{
    static auto function = td::Ref{Function{"getTransactions", make_header_params(), {}, {output_type()}}};
    TRY_RESULT(body, function->encode_input(empty_function_call()))
    return std::make_tuple(function, td::Ref<vm::Cell>{}, std::move(body));
}

auto GetTransactions::handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status
{
    TRY_STATUS(check_output<GetTransactions>(result))
    const auto& array = result[0]->as<ValueArray>();

    Result deserialized;
    deserialized.reserve(array.values.size());
    for (const auto& item : array.values) {
        deserialized.emplace_back(decode_transaction(item));
    }

    promise.set_result(std::move(deserialized));
    return td::Status::OK();
}

// get_transaction_ids

GetTransactionIds::GetTransactionIds(Action::Handler&& promise)
    : Action{std::move(promise)}
{
}

auto GetTransactionIds::output_type() -> ftabi::ParamRef
{
    static ParamRef param{ParamArray{"ids", ParamUint{"id", 64}}};
    return param;
}

auto GetTransactionIds::create_message() -> td::Result<EncodedMessage>
{
    static auto function = td::Ref{Function{"getTransactionIds", make_header_params(), {}, {output_type()}}};
    TRY_RESULT(body, function->encode_input(empty_function_call()))
    return std::make_tuple(function, td::Ref<vm::Cell>{}, std::move(body));
}

auto GetTransactionIds::handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status
{
    TRY_STATUS(check_output<GetTransactionIds>(result))
    const auto& array = result[0]->as<ValueArray>();

    Result deserialized;
    deserialized.reserve(array.values.size());
    for (const auto& item : array.values) {
        deserialized.emplace_back(item->as<ValueInt>().get<td::uint64>());
    }

    promise.set_result(deserialized);
    return td::Status::OK();
}

// get_custodians

GetCustodians::GetCustodians(Action::Handler&& promise)
    : Action{std::move(promise)}
{
}

auto GetCustodians::output_type() -> ftabi::ParamRef
{
    static ParamRef param{ParamArray{
        "custodians",
        ParamTuple{
            "custodian",            //
            ParamUint{"index", 8},  //
            ParamUint{"pubkey", 256}}}};
    return param;
}

auto GetCustodians::create_message() -> td::Result<EncodedMessage>
{
    static auto function = td::Ref{Function{"getCustodians", make_header_params(), {}, {output_type()}}};
    TRY_RESULT(body, function->encode_input(empty_function_call()))
    return std::make_tuple(function, td::Ref<vm::Cell>{}, std::move(body));
}

auto GetCustodians::handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status
{
    TRY_STATUS(check_output<GetCustodians>(result))
    const auto& array = result[0]->as<ValueArray>();

    Result deserialized;
    deserialized.reserve(array.values.size());
    for (const auto& item : array.values) {
        deserialized.emplace_back(decode_custodian(item));
    }

    promise.set_result(std::move(deserialized));
    return td::Status::OK();
}
}  // namespace app::msig
