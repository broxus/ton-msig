#include "Wallet.hpp"

#include <ton/lite-tl.hpp>

namespace app
{
void Wallet::start_up()
{
    auto last_block_handler = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_masterchainInfo>> R) {
        if (R.is_error()) {
            td::actor::send_closure(SelfId, &Wallet::check, R.move_as_error());
        }
        else {
            td::actor::send_closure(SelfId, &Wallet::got_last_block_state, R.move_as_ok());
        }
    });
    client_.send_query(lite_api::liteServer_getMasterchainInfo(), std::move(last_block_handler));
    pending_queries_ = 1;
}

auto Wallet::process_result() -> td::Status
{
    TRY_RESULT(encoded_body, context_->create_body())
    TRY_RESULT(output, ftabi::run_smc_method(addr_, std::move(account_state_.info), std::move(encoded_body.first), std::move(encoded_body.second)))
    return context_->handle_result(std::move(output));
}

void Wallet::got_last_block_state(lite_api_ptr<lite_api::liteServer_masterchainInfo>&& last_block_state)
{
    last_block_id_ = ton::create_block_id(last_block_state->last_);

    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_accountState>> R) mutable {
        if (R.is_error()) {
            td::actor::send_closure(SelfId, &Wallet::check, R.move_as_error());
        }
        else {
            td::actor::send_closure(SelfId, &Wallet::got_account_state, R.move_as_ok());
        }
    });
    client_.send_query(lite_api::liteServer_getAccountState(ton::create_tl_lite_block_id(last_block_id_), to_lite_api(addr_)), std::move(P));
    pending_queries_++;

    check_finished();
}

void Wallet::got_account_state(lite_api_ptr<lite_api::liteServer_accountState>&& account_state)
{
    block::AccountState state;
    state.blk = ton::create_block_id(account_state->id_);
    state.shard_blk = ton::create_block_id(account_state->shardblk_);
    state.shard_proof = std::move(account_state->shard_proof_);
    state.proof = std::move(account_state->proof_);
    state.state = std::move(account_state->state_);
    auto info_r = state.validate(last_block_id_, block::StdAddress(addr_.workchain, addr_.addr));
    if (info_r.is_error()) {
        check(info_r.move_as_error());
        return;
    }
    auto info = info_r.move_as_ok();

    if (info.root.is_null()) {
        check(td::Status::Error("account is empty"));
        return;
    }

    account_state_.sync_utime = info.gen_utime;
    account_state_.last_transaction_lt = info.last_trans_lt;
    account_state_.last_transaction_hash = info.last_trans_hash;

    block::gen::Account::Record_account acc;
    block::gen::AccountStorage::Record store;
    block::CurrencyCollection balance;
    if (tlb::unpack_cell(info.root, acc) && tlb::csr_unpack(acc.storage, store) && balance.unpack(store.balance)) {
        account_state_.balance = balance.grams->to_long();
    }

    int tag = block::gen::t_AccountState.get_tag(*store.state);
    switch (tag) {
        case block::gen::AccountState::account_uninit:
            account_state_.status = AccountStatus::uninit;
            break;
        case block::gen::AccountState::account_frozen:
            account_state_.status = AccountStatus::frozen;
            break;
        case block::gen::AccountState::account_active:
            account_state_.status = AccountStatus::active;
            break;
        default:
            account_state_.status = AccountStatus::unknown;
            break;
    }

    account_state_.info = std::move(info);

    check_finished();
}

void Wallet::check_finished()
{
    if (!--pending_queries_) {
        check(process_result());
        stop();
    }
}

void Wallet::check(td::Status status)
{
    if (status.is_error()) {
        LOG(ERROR) << status.move_as_error().message();
        stop();
    }
}

}  // namespace app
