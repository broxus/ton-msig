#include <res/mainnet_config_json.h>
#include <td/utils/JsonBuilder.h>
#include <td/utils/port/signals.h>
#include <tdutils/td/utils/filesystem.h>
#include <tonlib/keys/Mnemonic.h>

#include <CLI/CLI.hpp>
#include <cppcodec/hex_lower.hpp>
#include <iostream>

#include "App.hpp"

using namespace app;

static auto now_ms() -> td::uint64
{
    const auto duration = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

template <typename T>
static auto check_result(td::Result<T>&& result, const std::string& prefix = "") -> T
{
    if (result.is_error()) {
        std::cerr << result.move_as_error_prefix(prefix).message().c_str() << std::endl;
        std::exit(1);
    }
    return result.move_as_ok();
}

static auto is_mnemonics(const std::string& str) -> bool
{
    size_t word_count = 1;
    for (size_t i = 0; i < str.size(); ++i) {
        const auto c = str[i];

        const auto after_space = i != 0 && str[i - 1] == ' ';
        const auto is_space = c == ' ';

        if (is_space && after_space || !is_space && (!td::is_alpha(c) || !std::islower(c))) {
            return false;
        }
        else if (is_space) {
            ++word_count;
        }
    }
    return word_count == 12;
}

static auto load_key(const std::string& str) -> td::Result<td::Ed25519::PrivateKey>
{
    if (is_mnemonics(str)) {
        TRY_RESULT(mnemonic, tonlib::Mnemonic::create(td::SecureString{str}, {}))
        return mnemonic.to_private_key();
    }
    else {
        TRY_RESULT(keys_file, td::read_file(str))
        TRY_RESULT(json, td::json_decode(keys_file.as_slice()))
        auto& root = json.get_object();
        TRY_RESULT(secret, td::get_json_object_string_field(root, "secret", false))

        td::Bits256 private_key_data{};
        if (private_key_data.from_hex(secret) <= 0) {
            return td::Status::Error("Invalid secret");
        }

        return ton::privkeys::Ed25519{private_key_data.as_slice()}.export_key();
    }
}

struct AddressValidator : public CLI::Validator {
    constexpr static auto type_name = "ADDRESS";

    AddressValidator()
        : CLI::Validator(type_name)
    {
        func_ = [](const std::string& str) {
            if (!block::StdAddress{}.parse_addr(str)) {
                return "Invalid contract address: " + str;
            }
            return std::string{};
        };
    }
};

struct MnemonicsValidator : public CLI::Validator {
    constexpr static auto type_name = "MNEMONICS";

    MnemonicsValidator()
        : CLI::Validator(type_name)
    {
        func_ = [](const std::string& str) {
            if (!is_mnemonics(str)) {
                return "Invalid signature words: " + str;
            }
            return std::string{};
        };
    }
};

struct TonValidator : public CLI::Validator {
    TonValidator()
        : CLI::Validator("TON")
    {
        func_ = [](std::string& str) -> std::string {
            constexpr auto error_prefix = "Invalid TON value: ";

            if (str.empty()) {
                return error_prefix;
            }

            bool is_nano = str[0] == 'T', is_valid = true, has_digit = false, has_dot = false;
            auto dot_pos = std::string::npos;
            size_t decimals = 0;

            for (size_t i = is_nano; i < str.size(); ++i) {
                const auto c = str[i];

                const auto is_dot = c == '.' || c == ',';
                const auto is_digit = td::is_digit(c);

                if (!is_nano && is_dot || is_dot && (has_dot || !has_digit) || !is_dot && (!is_digit || has_dot && ++decimals > 9)) {
                    is_valid = false;
                    break;
                }

                if (is_dot) {
                    has_dot = true;
                    dot_pos = i;
                }

                if (is_digit) {
                    has_digit = true;
                }
            }

            if (!is_valid || (str.size() - is_nano) == 0) {
                return error_prefix + str;
            }

            if (dot_pos != std::string::npos) {
                str.erase(dot_pos, 1);
            }
            if (is_nano) {
                str.erase(0, 1);
                str += std::string(9u - decimals, '0');
            }

            return std::string{};
        };
    }
};

template <typename T>
auto create_handler(td::actor::ActorId<App>&& actor_id, std::function<void(T&&)>&& formatter) -> td::Promise<T>
{
    return td::PromiseCreator::lambda([actor_id = std::move(actor_id), formatter = std::move(formatter)](td::Result<T> R) {
        if (R.is_error()) {
            std::cerr << R.move_as_error().message().str() << std::endl;
        }
        else {
            formatter(R.move_as_ok());
        }
        td::actor::send_closure(actor_id, &App::close);
    });
}

int main(int argc, char** argv)
{
    td::actor::ActorOwn<App> app;
    std::function<std::unique_ptr<ActionBase>(td::actor::ActorId<App> &&)> action;

    CLI::App cmd{"ton-msig"};
    cmd.get_formatter()->column_width(42);

    block::StdAddress address;
    auto address_option = cmd.add_option_function<std::string>(
                                 "addr",
                                 [&](const std::string& addr) { CHECK(address.parse_addr(addr)) },
                                 "Wallet contract address")
                              ->type_name(AddressValidator::type_name)
                              ->check(AddressValidator{});

    int verbosity_level = verbosity_INFO;
    cmd.add_option("-v,--verbose", verbosity_level, "Verbosity level", true);

    td::size_t thread_count = 2u;
    cmd.add_option("-t,--threads", thread_count, "Thread count", true)->check(CLI::PositiveNumber);

    td::BufferSlice global_config{MAINNET_CONFIG_JSON, std::size(MAINNET_CONFIG_JSON)};
    cmd.add_option_function<std::string>(
           "-c,--config",
           [&](const std::string& path) { global_config = check_result(td::read_file(path)); },
           "Path to global config")
        ->check(CLI::ExistingFile);

    // subcommands
    bool all_balance = false;
    bool bounce = true;
    block::StdAddress dest{};
    td::BigInt256 value{};
    td::Ref<vm::Cell> payload{vm::CellBuilder{}.finalize()};
    td::uint64 transaction_id{};
    td::uint32 mask{};
    td::uint8 index{};

    std::optional<td::Ed25519::PrivateKey> key;
    const auto add_signature_option = [&key](CLI::App* subcommand) -> CLI::Option* {
        return subcommand
            ->add_option_function<std::string>(
                "-s,--sign",
                [&](const std::string& key_data) { key = check_result(load_key(key_data)); },
                "Signature for remote calls")
            ->check(CLI::ExistingFile | MnemonicsValidator{})
            ->required();
    };

    bool force_local = false;
    const auto add_force_local_option = [&force_local](CLI::App* subcommand) -> CLI::Option* {
        return subcommand->add_flag("--local", force_local, "Force local execution");
    };

    cmd.add_subcommand("genkeypair", "Generate new keypair")->callback([&] {
        const auto private_key = ton::privkeys::Ed25519::random().export_key();
        const auto public_key = check_result(private_key.get_public_key());

        std::cout << "{\n"
                  << R"(  "public": ")" << cppcodec::hex_lower::encode(public_key.as_octet_string()) << "\",\n"
                  << R"(  "secret": ")" << cppcodec::hex_lower::encode(private_key.as_octet_string()) << "\"\n"
                  << "}" << std::endl;

        std::exit(0);
    });

    auto* cmd_submit_transaction = cmd.add_subcommand("submitTransaction", "Create new transaction")->needs(address_option);
    cmd_submit_transaction
        ->add_option_function<std::string>(
            "dest",
            [&](const std::string& addr) { CHECK(dest.parse_addr(addr)) },
            "Destination address")
        ->required()
        ->check(AddressValidator{});
    cmd_submit_transaction
        ->add_option_function<std::string>(
            "value",
            [&](const std::string& v) { CHECK(value.parse_dec(v) > 0) },
            "Message value in TON")
        ->required()
        ->transform(TonValidator{});
    cmd_submit_transaction->add_option("--all-balance", all_balance, "Send all balance and delete contract", true);
    cmd_submit_transaction->add_option("--bounce", bounce, "Return message back when it is send to uninitialized address", true);
    cmd_submit_transaction->add_option_function<std::string>(
        "--payload",
        [&](const std::string& str) {
            if (str.empty()) {
                return;
            }
            const auto decoded = check_result(td::base64_decode(str), "Failed to deserialize payload");
            payload = check_result(vm::std_boc_deserialize(decoded));
        },
        "Serialized bag of cells of message body");
    add_signature_option(cmd_submit_transaction);
    add_force_local_option(cmd_submit_transaction);
    cmd_submit_transaction->callback([&] {
        action = [&](td::actor::ActorId<App>&& actor_id) {
            const auto now = now_ms();
            const auto expire = now / 1000 + 60;
            CHECK(key.has_value())

            LOG(DEBUG) << "Sending " << value.to_dec_string() << " TON from " << address.workchain << ":" << address.addr.to_hex() << " to " << dest.workchain
                       << ":" << dest.addr.to_hex();

            return std::make_unique<msig::SubmitTransaction>(
                create_handler<td::uint64>(
                    std::move(actor_id),
                    [&](td::uint64 transaction_id) { std::cout << "{\n  \"transactionId\": " << transaction_id << "\n}" << std::endl; }),
                force_local,
                now,
                expire,
                dest,
                value,
                bounce,
                all_balance,
                payload,
                *key);
        };
    });

    auto* cmd_confirm_transaction = cmd.add_subcommand("confirmTransaction", "Confirm pending transaction")->needs(address_option);
    cmd_confirm_transaction->add_option("transactionId", transaction_id, "Transaction id")->required();
    add_signature_option(cmd_confirm_transaction);
    add_force_local_option(cmd_confirm_transaction);
    cmd_confirm_transaction->callback([&] {
        action = [&](td::actor::ActorId<App>&& actor_id) {
            const auto now = now_ms();
            const auto expire = now / 1000 + 60;
            CHECK(key.has_value())

            LOG(DEBUG) << "Confirming " << transaction_id << " for " << address.workchain << ":" << address.addr.to_hex();

            return std::make_unique<msig::ConfirmTransaction>(
                create_handler<std::nullopt_t>(std::move(actor_id), [&](std::nullopt_t) { std::cout << "{}" << std::endl; }),
                force_local,
                now,
                expire,
                transaction_id,
                *key);
        };
    });

    auto* cmd_is_confirmed = cmd.add_subcommand("isConfirmed", "Check if transactions are confirmed")->needs(address_option);
    cmd_is_confirmed->add_option("mask", mask, "Mask")->required()->check(CLI::PositiveNumber);
    cmd_is_confirmed->add_option("index", index, "Index")->required()->check(CLI::PositiveNumber);
    cmd_is_confirmed->callback([&] {
        action = [&](td::actor::ActorId<App>&& actor_id) {
            return std::make_unique<msig::IsConfirmed>(
                create_handler<bool>(
                    std::move(actor_id),
                    [&](bool confirmed) { std::cout << "{\n  \"confirmed\": " << (confirmed ? "true" : "false") << "\n}" << std::endl; }),
                mask,
                index);
        };
    });

    cmd.add_subcommand("getParameters", "Get msig parameters")->needs(address_option)->callback([&] {
        action = [](td::actor::ActorId<App>&& actor_id) {
            return std::make_unique<msig::GetParameters>(create_handler<msig::Parameters>(std::move(actor_id), [&](msig::Parameters&& param) {
                std::cout << "{\n"                                                                                                //
                          << R"(  "max_queued_transactions": )" << static_cast<uint32_t>(param.max_queued_transactions) << ",\n"  //
                          << R"(  "max_custodian_count": )" << static_cast<uint32_t>(param.max_custodian_count) << ",\n"          //
                          << R"(  "expiration_time": )" << param.expiration_time << ",\n"                                         //
                          << R"(  "min_value": ")" << param.min_value << "\",\n"                                                  //
                          << R"(  "required_txn_confirms": )" << static_cast<uint32_t>(param.required_txn_confirms) << "\n}"      //
                          << std::endl;
            }));
        };
    });

    auto print_transaction = [](const msig::Transaction& trans, size_t offset) {
        const std::string tab(offset, ' ');
        std::cout << tab << "{\n"
                  << tab << R"(  "id": )" << trans.id << ",\n"
                  << tab << R"(  "confirmationMask": )" << trans.confirmationMask << ",\n"
                  << tab << R"(  "signsRequired": )" << static_cast<uint32_t>(trans.signsRequired) << ",\n"
                  << tab << R"(  "signsReceived": )" << static_cast<uint32_t>(trans.signsReceived) << ",\n"
                  << tab << R"(  "creator": ")" << trans.creator.to_hex_string() << "\",\n"
                  << tab << R"(  "index": )" << static_cast<uint32_t>(trans.index) << ",\n"
                  << tab << R"(  "dest": ")" << trans.dest.workchain << ":" << trans.dest.addr.to_hex() << "\",\n"
                  << tab << R"(  "value": ")" << trans.value.to_dec_string() << "\",\n"
                  << tab << R"(  "send_flags": )" << trans.send_flags << ",\n"
                  << tab << R"(  "bounce": )" << (trans.bounce ? "true" : "false") << "\n"
                  << tab << "}";
    };

    auto* cmd_get_transaction = cmd.add_subcommand("getTransaction", "Get transaction info")->needs(address_option);
    cmd_get_transaction->add_option("transactionId", transaction_id, "Transaction id")->required()->check(CLI::PositiveNumber);
    cmd_get_transaction->callback([&] {
        action = [&](td::actor::ActorId<App>&& actor_id) {
            using Result = msig::GetTransaction::Result;
            return std::make_unique<msig::GetTransaction>(
                create_handler<Result>(
                    std::move(actor_id),
                    [&](Result&& transaction) {
                        print_transaction(transaction, 0);
                        std::cout << std::endl;
                    }),
                transaction_id);
        };
    });

    cmd.add_subcommand("getTransactions", "Get pending transactions")->needs(address_option)->callback([&] {
        action = [&](td::actor::ActorId<App>&& actor_id) {
            using Result = msig::GetTransactions::Result;
            return std::make_unique<msig::GetTransactions>(create_handler<Result>(std::move(actor_id), [&](Result&& transactions) {
                if (transactions.empty()) {
                    std::cout << "[]" << std::endl;
                    return;
                }
                std::cout << "[\n";
                for (size_t i = 0; i < transactions.size(); ++i) {
                    print_transaction(transactions[i], 2);
                    if (i + 1 < transactions.size()) {
                        std::cout << ",";
                    }
                    std::cout << "\n";
                }
                std::cout << "]" << std::endl;
            }));
        };
    });

    cmd.add_subcommand("getTransactionIds", "Get ids of pending transactions")->needs(address_option)->callback([&] {
        action = [](td::actor::ActorId<App>&& actor_id) {
            using Result = msig::GetTransactionIds::Result;
            return std::make_unique<msig::GetTransactionIds>(create_handler<Result>(std::move(actor_id), [&](Result&& ids) {
                if (ids.empty()) {
                    std::cout << "[]" << std::endl;
                    return;
                }
                std::cout << "[\n";
                for (size_t i = 0; i < ids.size(); ++i) {
                    std::cout << "  " << ids[i];
                    if (i + 1 < ids.size()) {
                        std::cout << ",";
                    }
                    std::cout << "\n";
                }
                std::cout << "]" << std::endl;
            }));
        };
    });

    cmd.add_subcommand("getCustodians", "Get owners of this wallet")->needs(address_option)->callback([&] {
        action = [](td::actor::ActorId<App>&& actor_id) {
            using Result = msig::GetCustodians::Result;
            return std::make_unique<msig::GetCustodians>(create_handler<Result>(std::move(actor_id), [&](Result&& custodians) {
                if (custodians.empty()) {
                    std::cout << "[]" << std::endl;
                }
                std::cout << "[\n";
                for (size_t i = 0; i < custodians.size(); ++i) {
                    std::cout << "  {\n"                                                                      //
                              << R"(    "index": )" << static_cast<td::uint32>(custodians[i].index) << ",\n"  //
                              << R"(    "pubkey": ")" << custodians[i].pubkey.to_hex_string() << "\"\n  }";   //
                    if (i + 1 < custodians.size()) {
                        std::cout << ",";
                    }
                    std::cout << "\n";
                }
                std::cout << "]" << std::endl;
            }));
        };
    });

    cmd.require_subcommand();

    CLI11_PARSE(cmd, argc, argv)
    SET_VERBOSITY_LEVEL(verbosity_level);
    td::set_default_failure_signal_handler();

    td::actor::Scheduler scheduler({thread_count});
    scheduler.run_in_context([&] { app = td::actor::create_actor<App>("ton-msig", App::Options{std::move(global_config)}); });
    scheduler.run_in_context([&] {
        if (action) {
            auto request = action(app.get());
            td::actor::send_closure(app, &App::make_request, address, std::move(request));
        }
        app.release();
    });
    scheduler.run();
    return 0;
}
