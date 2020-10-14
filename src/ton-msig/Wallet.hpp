#pragma once

#include <td/actor/actor.h>
#include <tonlib/ExtClient.h>
#include <tonlib/ExtClientOutbound.h>
#include <tonlib/LastBlock.h>
#include <tonlib/LastConfig.h>
#include <tonlib/Stuff.h>
#include <tonlib/TonlibCallback.h>

#include <ftabi/Abi.hpp>
#include <variant>

#include "Action.hpp"
#include "Stuff.hpp"

namespace app
{
using namespace tonlib;

class Wallet final : public td::actor::Actor {
    enum class Mode {
        get_account_info,
        send_message,
    };

    enum class State {
        getting_account_info,
        waiting_transaction,
        waiting_transaction_sleep,
    };

public:
    constexpr static td::Slice actor_name = "Wallet";

    struct BriefAccountInfo {
        AccountStatus status{AccountStatus::uninit};
        td::RefInt256 balance{};
        ton::LogicalTime last_transaction_lt{};
        td::Bits256 last_transaction_hash{};
    };

    using AccountInfoHandler = td::Promise<BriefAccountInfo>;

    Wallet(ExtClientRef ext_client_ref, td::actor::ActorShared<> parent, const block::StdAddress& addr, AccountInfoHandler&& promise);
    Wallet(ExtClientRef ext_client_ref, td::actor::ActorShared<> parent, const block::StdAddress& addr, std::unique_ptr<ActionBase>&& context);

private:
    void start_up() final;
    void loop() final;

    void get_last_block_state();
    void got_last_block_state(lite_api_ptr<lite_api::liteServer_masterchainInfo>&& last_block_state);

    void get_account_state();
    void got_account_state(lite_api_ptr<lite_api::liteServer_accountState>&& account_state);

    void get_last_transaction();
    void got_last_transaction(lite_api_ptr<lite_api::liteServer_transactionList>&& transactions_list);

    auto run_local() -> td::Status;
    auto run_remote() -> td::Status;

    void send_message(td::BufferSlice&& message);
    void sent_message(lite_api_ptr<lite_api::liteServer_sendMsgStatus>&& send_msg_status);

    auto found_transaction(block::gen::Transaction::Record&& transaction) -> td::Status;

    void hangup() final { finish(TonlibError::Cancelled()); }

    void check(td::Status status);
    void finish(td::Status status);

    td::actor::ActorShared<> parent_;
    ExtClient client_;

    Mode mode_{};
    State state_{};
    block::StdAddress addr_;
    ton::BlockIdExt last_block_id_{};
    block::AccountState::Info account_info_{};

    ton::LogicalTime first_transaction_lt_{};
    ton::Bits256 first_transaction_hash_{};

    ton::LogicalTime last_transaction_lt_{};
    ton::Bits256 last_transaction_hash_{};

    td::uint32 expires_at_{};

    ftabi::FunctionRef function_{};
    vm::CellHash message_hash_{};

    std::unique_ptr<ActionBase> context_{};
    AccountInfoHandler account_info_handler_{};
};

}  // namespace app
