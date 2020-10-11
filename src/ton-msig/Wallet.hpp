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
    struct AccountState {
        ton::UnixTime sync_utime{};
        td::int64 balance{};
        AccountStatus status{};
        ton::LogicalTime last_transaction_lt{};
        block::AccountState::Info info;
        ton::Bits256 last_transaction_hash;
    };

public:
    template <typename T>
    struct Action {
        static_assert(std::is_base_of_v<ActionBase, T>);
    };

    template <typename T, typename... Args>
    Wallet(
        ExtClientRef ext_client_ref,
        td::actor::ActorShared<> parent,
        Action<T>,
        const block::StdAddress& addr,
        typename T::Handler&& promise,
        Args&&... args)
        : parent_{std::move(parent)}
        , addr_{addr}
        , action_{T::id}
        , context_{std::make_unique<T>(std::move(promise), std::forward<Args>(args)...)}
    {
        client_.set_client(std::move(ext_client_ref));
    }

private:
    void start_up() final;

    auto process_result() -> td::Status;

    void got_last_block_state(lite_api_ptr<lite_api::liteServer_masterchainInfo>&& last_block_state);
    void got_account_state(lite_api_ptr<lite_api::liteServer_accountState>&& account_state);

    void hangup() final { check(TonlibError::Cancelled()); }

    void check_finished();
    void check(td::Status status);

    td::actor::ActorShared<> parent_;
    ExtClient client_;
    td::int32 pending_queries_ = 0;

    int action_{};
    block::StdAddress addr_;
    ton::BlockIdExt last_block_id_{};
    AccountState account_state_{};

    std::unique_ptr<ActionBase> context_{};
};

}  // namespace app
