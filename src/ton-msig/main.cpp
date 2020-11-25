#include <res/config.h>
#include <res/mainnet_config_json.h>
#include <td/utils/JsonBuilder.h>
#include <td/utils/port/signals.h>
#include <tdutils/td/utils/filesystem.h>

#include <cppcodec/hex_lower.hpp>
#include <iostream>

#include "App.hpp"
#include "Cli.hpp"
#include "Contract.hpp"
#include "Mnemonic.hpp"

using namespace app;

static struct SharedStatus {
    void set(int code) { status.store(code); }
    [[nodiscard]] auto get() const { return status.load(std::memory_order_relaxed); }

private:
    std::atomic_int status{0};
} shared_execution_status = {};

template <typename T>
auto create_handler(const td::actor::ActorId<App>& actor_id, std::function<void(T&&)>&& formatter) -> td::Promise<T>
{
    return td::PromiseCreator::lambda([actor_id, formatter = std::move(formatter)](td::Result<T> R) {
        if (R.is_error()) {
            std::cerr << R.move_as_error().message().str() << std::endl;
            shared_execution_status.set(1);
        }
        else {
            formatter(R.move_as_ok());
        }
        td::actor::send_closure(actor_id, &App::close);
    });
}

template <typename T>
void print_as_json(T&& value)
{
    std::cout << nlohmann::json(value).dump(4) << std::endl;
}

template <>
void print_as_json<std::nullopt_t>(std::nullopt_t&& value)
{
    std::cout << "{}" << std::endl;
}

int main(int argc, char** argv)
{
    td::actor::ActorOwn<App> app;

    std::function<std::unique_ptr<ActionBase>(const td::actor::ActorId<App>&)> action_make_request;
    std::function<Wallet::FindMessage(const td::actor::ActorId<App>&)> action_find_message;
    std::function<td::Promise<Wallet::BriefAccountInfo>(const td::actor::ActorId<App>&)> action_get_account_info;

    CLI::App cmd{PROJECT_NAME};
    cmd.get_formatter()->column_width(45);
    cmd.set_help_all_flag("--help-all", "Print extended help message and exit");
    cmd.set_version_flag("-v,--version", PROJECT_VER);

    block::StdAddress address;
    auto address_option = cmd.add_option_function<std::string>(
                                 "addr",
                                 [&](const std::string& addr) { CHECK(address.parse_addr(addr)) },
                                 "Wallet contract address")
                              ->type_name(AddressValidator::type_name)
                              ->check(AddressValidator{});

    int verbosity_level = verbosity_INFO;
    cmd.add_option("-l,--log-level", verbosity_level, "Log verbosity level", true)->check(CLI::Range(1, 7));

    td::size_t thread_count = 2u;
    cmd.add_option("-t,--threads", thread_count, "Thread count", true)->check(CLI::PositiveNumber);

    td::BufferSlice global_config{MAINNET_CONFIG_JSON, std::size(MAINNET_CONFIG_JSON)};
    cmd.add_option_function<std::string>(
           "-c,--config",
           [&](const std::string& path) { global_config = check_result(td::read_file(path)); },
           "Path to global config")
        ->check(CLI::ExistingFile);

    // subcommands helpers

    std::optional<std::string> phrase;
    std::optional<td::Ed25519::PrivateKey> key;
    const auto add_signature_option = [&key, &phrase](CLI::App* subcommand, const char* name = "-s,--sign") -> CLI::Option* {
        return subcommand
            ->add_option_function<std::string>(
                name,
                [&](const std::string& key_data) { key = check_result(load_key(key_data, phrase)); },
                "Mnemonic or path to keypair file")
            ->transform(CLI::ExistingFile | MnemonicValidator{})
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

    std::optional<std::string> msg_info_path{};
    const auto add_msg_info_path_option = [&msg_info_path](CLI::App* subcommand) -> CLI::Option* {
        return subcommand->add_option("--save", msg_info_path, "Save message info to file");
    };

    td::uint32 msg_timeout{60};
    const auto add_timeout_option = [&msg_timeout](CLI::App* subcommand) -> CLI::Option* {
        return subcommand->add_option("--timeout", msg_timeout, "Set message expiration timeout in seconds", true)->check(CLI::Range(10, 86400));
    };

    // Subcommand: convert
    cmd.add_subcommand("convert", "Convert address into another formats")->needs(address_option)->callback([&] {
        nlohmann::json j;
        j["raw"] = std::to_string(address.workchain) + ":" + address.addr.to_hex();
        j["packed"] = (address.bounceable = false, address.rserialize());
        j["packedUrlSafe"] = address.rserialize(/*urlsafe*/ true);
        j["packedBounceable"] = (address.bounceable = true, address.rserialize());
        j["packedBounceableUrlSafe"] = address.rserialize(/*urlsafe*/ true);

        std::cout << j.dump(4) << std::endl;
        std::exit(0);
    });

    // Subcommand: getpubkey

    auto cmd_getpubkey = cmd.add_subcommand("getpubkey", "Get public key from private");
    cmd_getpubkey
        ->add_option_function<std::string>(
            "privkey",
            [&](const std::string& str) {
                key = td::Ed25519::PrivateKey{td::SecureString{str.data(), str.size()}};
            },
            "Private key hex")
        ->transform(KeyValidator{})
        ->required();
    cmd_getpubkey->callback([&] {
        CHECK(key.has_value())
        const auto public_key = check_result(key->get_public_key());
        std::cout << nlohmann::json{{"public", cppcodec::hex_lower::encode(public_key.as_octet_string())}}.dump(4) << std::endl;
        std::exit(0);
    });

    // Subcommand: generate

    bool gen_addr = true;

    auto* cmd_generate = cmd.add_subcommand("generate", "Generate new keypair and address");
    cmd_generate->add_option("-a,--addr", gen_addr, "Whether to generate an address", true);
    add_workchain_option(cmd_generate);
    add_signature_option(cmd_generate, "-f,--from")->required(false);
    cmd_generate->callback([&] {
        const auto from_existing = key.has_value();
        std::string new_phrase{};
        const auto private_key = from_existing ? std::move(key.value()) : check_result(mnemonic::generate_key(new_phrase));
        const auto public_key = check_result(private_key.get_public_key());

        nlohmann::json j{
            {"public", cppcodec::hex_lower::encode(public_key.as_octet_string())},
            {"secret", cppcodec::hex_lower::encode(private_key.as_octet_string())}};
        if (from_existing || gen_addr) {
            const auto addr = check_result(Contract::generate_addr(public_key));
            j["address"] = std::to_string(workchain) + ":" + addr.to_hex();
        }
        if (phrase.has_value()) {
            j["phrase"] = phrase.value();
        }
        else if (!new_phrase.empty()) {
            j["phrase"] = new_phrase;
        }

        std::cout << j.dump(4) << std::endl;
        std::exit(0);
    });

    // Subcommand: deploy

    std::vector<td::BigInt256> owners{};
    td::uint8 req_confirms{1};

    auto* cmd_deploy = cmd.add_subcommand("deploy", "Deploy new contract")->excludes(address_option);
    add_signature_option(cmd_deploy);
    add_workchain_option(cmd_deploy);
    // add_force_local_option(cmd_deploy); // will not work now
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
        ->transform(KeyValidator{})
        ->expected(-1)
        ->required();
    cmd_deploy->add_option("-r,--req-confirms", req_confirms, "Number of confirmations required for executing transaction", true)
        ->default_val(static_cast<td::uint16>(req_confirms))
        ->check(CLI::Range(1, 32));
    add_timeout_option(cmd_deploy);
    add_msg_info_path_option(cmd_deploy);
    cmd_deploy->callback([&] {
        const auto public_key = check_result(key->get_public_key());
        const auto addr = check_result(Contract::generate_addr(public_key));
        address = block::StdAddress{workchain, addr, false};

        action_make_request = [&](const td::actor::ActorId<App>& actor_id) {
            const auto now = now_ms();
            const auto expire = now / 1000 + msg_timeout;
            CHECK(key.has_value())

            LOG(DEBUG) << "Deploying contract to address " << address.workchain << ":" << address.addr.to_hex() << " with owners: ";
            for (const auto& owner : owners) {
                LOG(DEBUG) << "    " << owner.to_hex_string();
            }

            return std::make_unique<msig::Constructor>(
                create_handler<std::nullopt_t>(actor_id, [&](std::nullopt_t) { std::cout << "{}" << std::endl; }),
                force_local,
                now,
                expire,
                std::move(owners),
                req_confirms,
                *key,
                msg_info_path);
        };
    });

    // Subcommand: info

    cmd.add_subcommand("info", "Get account info")->needs(address_option)->callback([&] {
        action_get_account_info = [&](const td::actor::ActorId<App>& actor_id) {
            using Result = Wallet::BriefAccountInfo;
            return create_handler<Result>(actor_id, &print_as_json<Result>);
        };
    });

    // Subcommand: find

    MessageInfo message_info;
    bool dont_wait_until_appears = false;

    auto* cmd_find = cmd.add_subcommand("find", "Find entity by id")->require_subcommand()->needs(address_option);
    auto* cmd_find_message = cmd_find->add_subcommand("message", "Find message by hash");
    cmd_find_message
        ->add_option_function<std::string>(
            "hash",
            [&](const std::string& str) { message_info = check_result(load_message_info(str)); },
            "Message hash or path to message info")
        ->check(CLI::ExistingFile /* | HexValidator{} */)  // raw hash not supported yet
        ->required();
    cmd_find_message->add_flag("--no-wait", dont_wait_until_appears, "Don't wait for the message you are looking for");
    cmd_find_message->callback([&] {
        action_find_message = [&](const td::actor::ActorId<App>& actor_id) {
            using Result = Wallet::BriefMessageInfo;
            return Wallet::FindMessage{
                create_handler<Result>(actor_id, &print_as_json<Result>),
                message_info.hash,
                message_info.created_at,
                message_info.expires_at,
                !dont_wait_until_appears};
        };
    });

    // Subcommand: submitTransaction

    block::StdAddress dest{};
    td::BigInt256 value{};
    bool all_balance = false;
    bool bounce = true;
    td::Ref<vm::Cell> payload{vm::CellBuilder{}.finalize()};

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
    add_timeout_option(cmd_submit_transaction);
    add_msg_info_path_option(cmd_submit_transaction);
    cmd_submit_transaction->callback([&] {
        action_make_request = [&](const td::actor::ActorId<App>& actor_id) {
            const auto now = now_ms();
            const auto expire = now / 1000 + msg_timeout;
            CHECK(key.has_value())

            LOG(DEBUG) << "Sending " << value.to_dec_string() << " TON from " << address.workchain << ":" << address.addr.to_hex() << " to " << dest.workchain
                       << ":" << dest.addr.to_hex();

            using Request = msig::SubmitTransaction;
            return std::make_unique<Request>(
                create_handler<Request::Result>(actor_id, &print_as_json<Request::Result>),
                force_local,
                now,
                expire,
                dest,
                value,
                bounce,
                all_balance,
                payload,
                *key,
                msg_info_path);
        };
    });

    // Subcommand: confirmTransaction

    td::uint64 transaction_id{};

    auto* cmd_confirm_transaction = cmd.add_subcommand("confirmTransaction", "Confirm pending transaction")->needs(address_option);
    cmd_confirm_transaction->add_option("transactionId", transaction_id, "Transaction id")->required();
    add_signature_option(cmd_confirm_transaction);
    add_force_local_option(cmd_confirm_transaction);
    add_timeout_option(cmd_confirm_transaction);
    add_msg_info_path_option(cmd_confirm_transaction);
    cmd_confirm_transaction->callback([&] {
        action_make_request = [&](const td::actor::ActorId<App>& actor_id) {
            const auto now = now_ms();
            const auto expire = now / 1000 + msg_timeout;
            CHECK(key.has_value())

            LOG(DEBUG) << "Confirming " << transaction_id << " for " << address.workchain << ":" << address.addr.to_hex();

            using Request = msig::ConfirmTransaction;
            return std::make_unique<Request>(
                create_handler<Request::Result>(actor_id, &print_as_json<Request::Result>),
                force_local,
                now,
                expire,
                transaction_id,
                *key,
                msg_info_path);
        };
    });

    // Subcommand: isConfirmed

    td::uint32 mask{};
    td::uint8 index{};

    auto* cmd_is_confirmed = cmd.add_subcommand("isConfirmed", "Check if transactions are confirmed")->needs(address_option);
    cmd_is_confirmed->add_option("mask", mask, "Mask")->required()->check(CLI::PositiveNumber);
    cmd_is_confirmed->add_option("index", index, "Index")->required()->check(CLI::PositiveNumber);
    cmd_is_confirmed->callback([&] {
        action_make_request = [&](const td::actor::ActorId<App>& actor_id) {
            using Request = msig::IsConfirmed;
            return std::make_unique<Request>(create_handler<Request::Result>(actor_id, &print_as_json<Request::Result>), mask, index);
        };
    });

    // Subcommand: getParameters

    cmd.add_subcommand("getParameters", "Get msig parameters")->needs(address_option)->callback([&] {
        action_make_request = [](const td::actor::ActorId<App>& actor_id) {
            using Request = msig::GetParameters;
            return std::make_unique<Request>(create_handler<Request::Result>(actor_id, &print_as_json<Request::Result>));
        };
    });

    // Subcommand: getTransaction

    auto* cmd_get_transaction = cmd.add_subcommand("getTransaction", "Get transaction info")->needs(address_option);
    cmd_get_transaction->add_option("transactionId", transaction_id, "Transaction id")->required()->check(CLI::PositiveNumber);
    cmd_get_transaction->callback([&] {
        action_make_request = [&](const td::actor::ActorId<App>& actor_id) {
            using Request = msig::GetTransaction;
            return std::make_unique<Request>(create_handler<Request::Result>(actor_id, &print_as_json<Request::Result>), transaction_id);
        };
    });

    // Subcommand: getTransactions

    cmd.add_subcommand("getTransactions", "Get pending transactions")->needs(address_option)->callback([&] {
        action_make_request = [&](const td::actor::ActorId<App>& actor_id) {
            using Request = msig::GetTransactions;
            return std::make_unique<Request>(create_handler<Request::Result>(actor_id, &print_as_json<Request::Result>));
        };
    });

    // Subcommand: getTransactionIds

    cmd.add_subcommand("getTransactionIds", "Get ids of pending transactions")->needs(address_option)->callback([&] {
        action_make_request = [](const td::actor::ActorId<App>& actor_id) {
            using Request = msig::GetTransactionIds;
            return std::make_unique<Request>(create_handler<Request::Result>(actor_id, &print_as_json<Request::Result>));
        };
    });

    // Subcommand: getCustodians

    cmd.add_subcommand("getCustodians", "Get owners of this wallet")->needs(address_option)->callback([&] {
        action_make_request = [](const td::actor::ActorId<App>& actor_id) {
            using Request = msig::GetCustodians;
            return std::make_unique<Request>(create_handler<Request::Result>(actor_id, &print_as_json<Request::Result>));
        };
    });

    // Start application

    cmd.require_subcommand();

    CLI11_PARSE(cmd, argc, argv)
    SET_VERBOSITY_LEVEL(verbosity_level);
    td::set_default_failure_signal_handler();

    td::actor::Scheduler scheduler({thread_count});
    scheduler.run_in_context([&] { app = App::create({std::move(global_config)}); });
    scheduler.run_in_context([&] {
        if (action_make_request) {
            td::actor::send_closure(app, &App::make_request, address, action_make_request(app.get()));
        }
        else if (action_get_account_info) {
            td::actor::send_closure(app, &App::get_account_info, address, action_get_account_info(app.get()));
        }
        else if (action_find_message) {
            td::actor::send_closure(app, &App::find_message, address, action_find_message(app.get()));
        }
        app.release();
    });
    scheduler.run();
    return shared_execution_status.get();
}
