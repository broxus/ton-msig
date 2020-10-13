#include <td/utils/port/signals.h>
#include <tdutils/td/utils/filesystem.h>

#include <CLI/CLI.hpp>
#include <iostream>

#include "App.hpp"

using namespace app;

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
            size_t word_count = 1;
            bool is_valid = true;
            for (size_t i = 0; i < str.size(); ++i) {
                const auto c = str[i];

                const auto after_space = i != 0 && str[i - 1] == ' ';
                const auto is_space = c == ' ';

                if (is_space && after_space || !is_space && (!td::is_alpha(c) || !std::islower(c))) {
                    is_valid = false;
                    break;
                }
                else if (is_space) {
                    ++word_count;
                }
            }

            if (word_count != 12 || !is_valid) {
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
            }

            return std::string{};
        };
    }
};

int main(int argc, char** argv)
{
    td::set_default_failure_signal_handler();

    td::actor::ActorOwn<App> app;
    std::unique_ptr<ActionBase> action;

    CLI::App cmd{"ton-msig"};

    std::string address;
    auto address_option = cmd.add_option("addr", address, "Wallet contract address")->type_name(AddressValidator::type_name)->check(AddressValidator{});

    std::string signature_value;
    auto signature_option = cmd.add_option("-s,--sign", signature_value, "Signature for remote calls")->check(CLI::ExistingFile | MnemonicsValidator{});

    int verbosity_level = verbosity_INFO;
    cmd.add_option("-v,--verbose", verbosity_level, "Verbosity level", true);

    td::size_t thread_count = 2u;
    cmd.add_option("-t,--threads", thread_count, "Thread count", true)->check(CLI::PositiveNumber);

    std::string global_config_path;
    cmd.add_option("-c,--config", global_config_path, "Path to global config")->check(CLI::ExistingFile)->required();

    // subcommands
    bool all_balance = false;
    bool bounce = true;
    std::string dest{};
    std::string value{};
    td::uint64 transactionId{};

    auto* cmd_submit_transaction = cmd.add_subcommand("submitTransaction", "Create new transaction")->needs(address_option)->needs(signature_option);
    cmd_submit_transaction->add_option("dest", dest, "Destination address")->required()->check(AddressValidator{});
    cmd_submit_transaction->add_option("value", value, "Message value in TON")->required()->transform(TonValidator{});
    cmd_submit_transaction->add_option("--all-balance", all_balance, "Send all balance and delete contract", true);
    cmd_submit_transaction->add_option("--bounce", bounce, "Return message back when it is send to uninitialized address", true);

    auto* cmd_confirm_transaction = cmd.add_subcommand("confirmTransaction", "Confirm pending transaction")->needs(address_option)->needs(signature_option);
    cmd_confirm_transaction->add_option("transactionId", transactionId, "Transaction id")->required();

    cmd.add_subcommand("getParameters", "Get msig parameters")->needs(address_option)->callback([&] {
        auto P = td::PromiseCreator::lambda([](td::Result<msig::GetParameters::Result> R) {
            if (R.is_error()) {
                LOG(ERROR) << R.move_as_error();
            }
            else {
                auto parameters = R.move_as_ok();
                LOG(INFO) << parameters.min_value.to_dec_string();
                LOG(INFO) << parameters.required_txn_confirms;
            }
        });
        action = std::make_unique<msig::GetParameters>(std::move(P));
    });

    cmd.add_subcommand("getTransactions", "List all pending transactions")->needs(address_option);

    CLI11_PARSE(cmd, argc, argv)
    SET_VERBOSITY_LEVEL(verbosity_level);

    block::StdAddress smc_address;
    smc_address.parse_addr(address);

    auto global_config_r = td::read_file(global_config_path);
    if (global_config_r.is_error()) {
        LOG(ERROR) << global_config_r.move_as_error();
        std::exit(1);
    }

    td::actor::Scheduler scheduler({thread_count});
    scheduler.run_in_context([&] { app = td::actor::create_actor<App>("ton-msig", App::Options{global_config_r.move_as_ok()}); });
    scheduler.run_in_context([&] {
        if (action != nullptr) {
            td::actor::send_closure(app, &App::make_request, smc_address, std::move(action));
        }
        app.release();
    });
    scheduler.run();
    return 0;
}
