#include "Action.hpp"

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
auto empty_function(const char* name) -> FunctionRef
{
    static td::Ref<ftabi::Function> function = td::Ref{Function{name, make_header_params(), {}, {T::output_type()}}};
    return function;
}

template <typename T>
auto create_function_body(const char* name, FunctionCallRef&& call = empty_function_call()) -> td::Result<EncodedBody>
{
    auto function = empty_function<T>(name);
    TRY_RESULT(body, function->encode_input(call))
    return std::make_pair(function, std::move(body));
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

// is_confirmed

IsConfirmed::IsConfirmed(Action::Handler&& promise)
    : Action{std::move(promise)}
{
}

auto IsConfirmed::create_body() -> td::Result<EncodedBody>
{
    return td::Result<EncodedBody>();
}

auto IsConfirmed::handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status
{
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

auto GetParameters::create_body() -> td::Result<EncodedBody>
{
    return create_function_body<GetParameters>("getParameters");
}

auto GetParameters::handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status
{
    LOG(WARNING) << "Result size: " << result.size();
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

auto GetTransaction::create_body() -> td::Result<EncodedBody>
{
    return create_function_body<GetTransaction>(
        "getTransaction",
        FunctionCallRef{FunctionCall{{make_value(ParamUint{"id", 64}, td::make_bigint(transaction_id_))}}});
}

auto GetTransaction::handle_result(std::vector<ftabi::ValueRef>&& result) -> td::Status
{
    TRY_STATUS(check_output<GetTransactions>(result))
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
    static ParamRef param{ParamArray{
        "transactions",
        ParamTuple{
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
        }}};

    return param;
}

auto GetTransactions::create_body() -> td::Result<EncodedBody>
{
    return create_function_body<GetTransactions>("getTransactions");
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

auto GetTransactionIds::create_body() -> td::Result<EncodedBody>
{
    return create_function_body<GetTransactionIds>("getTransactionIds");
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

auto GetCustodians::create_body() -> td::Result<EncodedBody>
{
    return create_function_body<GetCustodians>("getCustodians");
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