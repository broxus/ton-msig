#include <res/mainnet_config_json.h>
#include <td/utils/JsonBuilder.h>
#include <td/utils/port/signals.h>
#include <tdutils/td/utils/filesystem.h>
#include <tonlib/keys/Mnemonic.h>

#include <cppcodec/hex_lower.hpp>
#include <iostream>

#include "App.hpp"
#include "Cli.hpp"
#include "Contract.hpp"

using namespace app;

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
    std::vector<td::BigInt256> owners{};
    td::uint8 req_confirms{1};
    bool gen_addr = false;

    std::optional<td::Ed25519::PrivateKey> key;
    const auto add_signature_option = [&key](CLI::App* subcommand, const char* name = "-s,--sign") -> CLI::Option* {
        return subcommand
            ->add_option_function<std::string>(
                name,
                [&](const std::string& key_data) { key = check_result(load_key(key_data)); },
                "Path to keypair file")
            ->check(CLI::ExistingFile | MnemonicsValidator{})
            ->required();
    };

    bool force_local = false;
    const auto add_force_local_option = [&force_local](CLI::App* subcommand) -> CLI::Option* {
        return subcommand->add_flag("--local", force_local, "Force local execution");
    };

    ton::WorkchainId workchain{0};
    const auto add_workchain_option = [&workchain](CLI::App* subcommand) -> CLI::Option* {
        return subcommand->add_option("-w,--workchain", workchain, "Workchain")->check(CLI::Range(-1, 0));
    };

    auto* cmd_generate = cmd.add_subcommand("generate", "Generate new keypair");
    cmd_generate->add_flag("-a,--addr", gen_addr, "Whether to generate an address");
    add_workchain_option(cmd_generate);
    add_signature_option(cmd_generate, "-f,--from")->required(false);
    cmd_generate->callback([&] {
        const auto from_existing = key.has_value();
        const auto private_key = from_existing ? std::move(key.value()) : ton::privkeys::Ed25519::random().export_key();
        const auto public_key = check_result(private_key.get_public_key());

        std::cout << "{\n"
                  << R"(  "public": ")" << cppcodec::hex_lower::encode(public_key.as_octet_string()) << "\",\n"
                  << R"(  "secret": ")" << cppcodec::hex_lower::encode(private_key.as_octet_string()) << "\"";
        if (from_existing || gen_addr) {
            const auto addr = check_result(Contract::generate_addr(public_key));
            std::cout << ",\n  \"address\": \"" << workchain << ":" << addr.to_hex() << "\"";
        }
        std::cout << "\n}" << std::endl;

        std::exit(0);
    });

    auto* cmd_deploy = cmd.add_subcommand("deploy", "Deploy new contract")->excludes(address_option);
    add_signature_option(cmd_deploy);
    add_workchain_option(cmd_deploy);
    //add_force_local_option(cmd_deploy); // will not work now
    cmd_deploy
        ->add_option_function<std::vector<std::string>>(
            "-o,--owner",
            [&](const std::vector<std::string>& str) {
                for (const auto& item : str) {
                    td::BigInt256 owner;
                    CHECK(owner.import_bytes(reinterpret_cast<const unsigned char*>(item.c_str()), item.size(), false))
                    owners.emplace_back(owner);
                }
            },
            "Custodian public key")
        ->transform(PubKeyValidator{})
        ->expected(-1)
        ->required();
    cmd_deploy->add_option("-r,--req-confirms", req_confirms, "Number of confirmations required for executing transaction", true)
        ->default_val(static_cast<td::uint16>(req_confirms))
        ->check(CLI::Range(1, 32));
    cmd_deploy->callback([&] {
        const auto public_key = check_result(key->get_public_key());
        const auto addr = check_result(Contract::generate_addr(public_key));
        address = block::StdAddress{workchain, addr, false};

        action = [&](td::actor::ActorId<App>&& actor_id) {
            const auto now = now_ms();
            const auto expire = now / 1000 + 60;
            CHECK(key.has_value())

            LOG(DEBUG) << "Deploying contract to address " << address.workchain << ":" << address.addr.to_hex() << " with owners: ";
            for (const auto& owner : owners) {
                LOG(DEBUG) << "    " << owner.to_hex_string();
            }

            return std::make_unique<msig::Constructor>(
                create_handler<std::nullopt_t>(std::move(actor_id), [&](std::nullopt_t) { std::cout << "{}" << std::endl; }),
                force_local,
                now,
                expire,
                std::move(owners),
                req_confirms,
                *key);
        };
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
