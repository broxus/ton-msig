#pragma once

#include <tonlib/TonlibClient.h>

#include "Wallet.hpp"

namespace app
{
class App final : public td::actor::Actor {
public:
    struct Options {
        td::uint32 thread_count{2};
        td::BufferSlice config{};
    };

    explicit App(Options&& options);
    ~App() final;

private:
    void start_up() final;

    template <typename T, typename... Args>
    auto make_request(const block::StdAddress& addr, td::Promise<typename T::Result>&& promise, Args&&... args)
    {
        auto id = actor_id_++;
        actors_[id] = td::actor::create_actor<Wallet>(  //
            "Wallet",
            client_.get_client(),
            actor_shared(this, id),
            Wallet::Action<T>{},
            addr,
            std::move(promise),
            std::forward(args)...);
    }

    auto get_client_ref() -> tonlib::ExtClientRef;
    void init_ext_client();
    void init_last_block(tonlib::LastBlockState state);
    void init_last_config();

    void hangup_shared() final;
    void hangup() final;
    void tear_down() final;

    void try_stop();

    Options options_;
    tonlib::Config config_;
    std::shared_ptr<tonlib::KeyValue> kv_;

    bool is_closing_{false};
    td::uint32 ref_cnt_{1};

    td::actor::ActorOwn<ton::adnl::AdnlExtClient> raw_client_;
    td::actor::ActorOwn<tonlib::LastBlock> raw_last_block_;
    td::actor::ActorOwn<tonlib::LastConfig> raw_last_config_;
    tonlib::ExtClient client_;

    tonlib::LastBlockStorage last_block_storage_;
    std::string last_state_key_;

    td::CancellationTokenSource source_;

    std::map<td::int64, td::actor::ActorOwn<>> actors_;
    td::int64 actor_id_{1};
};

}  // namespace app