#include "Wallet.hpp"

#include <ton/lite-tl.hpp>

namespace app
{
Wallet::Wallet(ExtClientRef ext_client_ref, td::actor::ActorShared<> parent, const block::StdAddress& addr, AccountInfoHandler&& promise)
    : parent_{std::move(parent)}
    , mode_{Mode::get_account_info}
    , state_{State::getting_account_info}
    , addr_{addr}
    , account_info_handler_{std::move(promise)}
{
    client_.set_client(std::move(ext_client_ref));
}

Wallet::Wallet(ExtClientRef ext_client_ref, td::actor::ActorShared<> parent, const block::StdAddress& addr, std::unique_ptr<ActionBase>&& context)
    : parent_{std::move(parent)}
    , mode_{Mode::send_message}
    , state_{State::getting_account_info}
    , addr_{addr}
    , context_{std::move(context)}
{
    client_.set_client(std::move(ext_client_ref));
}

void Wallet::start_up()
{
    get_last_block_state();
}

void Wallet::loop()
{
    LOG(DEBUG) << "Loop called for state: " << static_cast<int>(state_);
    if (state_ == State::waiting_transaction_sleep) {
        state_ = State::waiting_transaction;
        get_last_block_state();
    }
}

void Wallet::get_last_block_state()
{
    LOG(DEBUG) << "get last block state";
    auto last_block_handler = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_masterchainInfo>> R) {
        if (R.is_error()) {
            td::actor::send_closure(SelfId, &Wallet::finish, R.move_as_error());
        }
        else {
            td::actor::send_closure(SelfId, &Wallet::got_last_block_state, R.move_as_ok());
        }
    });
    client_.send_query(lite_api::liteServer_getMasterchainInfo(), std::move(last_block_handler));
}

void Wallet::got_last_block_state(lite_api_ptr<lite_api::liteServer_masterchainInfo>&& last_block_state)
{
    last_block_id_ = ton::create_block_id(last_block_state->last_);

    LOG(DEBUG) << "got last block state" << last_block_id_.to_str();

    get_account_state();
}

void Wallet::get_account_state()
{
    LOG(DEBUG) << "get account state" << last_block_id_.to_str();

    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_accountState>> R) mutable {
        if (R.is_error()) {
            td::actor::send_closure(SelfId, &Wallet::finish, R.move_as_error());
        }
        else {
            td::actor::send_closure(SelfId, &Wallet::got_account_state, R.move_as_ok());
        }
    });
    client_.send_query(lite_api::liteServer_getAccountState(ton::create_tl_lite_block_id(last_block_id_), to_lite_api(addr_)), std::move(P));
}

void Wallet::got_account_state(lite_api_ptr<lite_api::liteServer_accountState>&& account_state)
{
    LOG(DEBUG) << "got account state" << last_block_id_.to_str();

    block::AccountState state;
    state.blk = ton::create_block_id(account_state->id_);
    state.shard_blk = ton::create_block_id(account_state->shardblk_);
    state.shard_proof = std::move(account_state->shard_proof_);
    state.proof = std::move(account_state->proof_);
    state.state = std::move(account_state->state_);
    auto info_r = state.validate(last_block_id_, block::StdAddress(addr_.workchain, addr_.addr));
    if (info_r.is_error()) {
        return finish(info_r.move_as_error());
    }
    account_info_ = info_r.move_as_ok();

    if (account_info_.root.is_null()) {
        if (mode_ == Mode::get_account_info) {
            account_info_handler_.set_result(BriefAccountInfo{});
            return finish(td::Status::OK());
        }
        else {
            return finish(td::Status::Error("account is empty"));
        }
    }

    const auto still_same_transaction = last_transaction_lt_ == account_info_.last_trans_lt &&  //
                                        last_transaction_hash_ == account_info_.last_trans_hash;

    last_transaction_lt_ = account_info_.last_trans_lt;
    last_transaction_hash_ = account_info_.last_trans_hash;

    LOG(DEBUG) << "previous transaction: " << last_transaction_lt_ << ":" << last_transaction_hash_.to_hex();

    switch (state_) {
        case State::getting_account_info: {
            switch (mode_) {
                case Mode::get_account_info: {
                    BriefAccountInfo brief_info{};
                    brief_info.last_transaction_lt = last_transaction_lt_;
                    brief_info.last_transaction_hash = last_transaction_hash_;
                    brief_info.sync_time = account_info_.gen_utime;

                    block::gen::Account::Record_account acc;
                    block::gen::AccountStorage::Record store;
                    block::CurrencyCollection balance;
                    if (tlb::unpack_cell(account_info_.root, acc) && tlb::csr_unpack(acc.storage, store) && balance.unpack(store.balance)) {
                        brief_info.balance = balance.grams;
                    }

                    int tag = block::gen::t_AccountState.get_tag(*store.state);
                    switch (tag) {
                        case block::gen::AccountState::account_uninit:
                            brief_info.status = AccountStatus::uninit;
                            break;
                        case block::gen::AccountState::account_frozen:
                            brief_info.status = AccountStatus::frozen;
                            break;
                        case block::gen::AccountState::account_active:
                            brief_info.status = AccountStatus::active;
                            break;
                        default:
                            brief_info.status = AccountStatus::unknown;
                            break;
                    }

                    account_info_handler_.set_value(std::move(brief_info));
                    return finish(td::Status::OK());
                }
                case Mode::send_message:
                    if (context_->is_get_method()) {
                        return finish(run_local());
                    }
                    else {
                        first_transaction_lt_ = last_transaction_lt_;
                        first_transaction_hash_ = last_transaction_hash_;
                        return check(run_remote());
                    }
                default:
                    break;
            }
        }
        case State::waiting_transaction: {
            if (still_same_transaction && account_info_.gen_utime > expires_at_) {
                return finish(td::Status::Error("message expired"));
            }

            if (still_same_transaction) {
                state_ = State::waiting_transaction_sleep;
                alarm_timestamp() = td::Timestamp::in(1.0);
            }
            else {
                get_last_transaction();
            }
            return;
        }
        default: {
            break;
        }
    }
    CHECK(false)
}

void Wallet::get_last_transaction()
{
    LOG(DEBUG) << "get last transaction " << last_transaction_lt_ << ":" << last_transaction_hash_.to_hex();
    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_transactionList>> R) mutable {
        if (R.is_error()) {
            td::actor::send_closure(SelfId, &Wallet::finish, R.move_as_error());
        }
        else {
            td::actor::send_closure(SelfId, &Wallet::got_last_transaction, R.move_as_ok());
        }
    });
    client_.send_query(lite_api::liteServer_getTransactions(1, to_lite_api(addr_), last_transaction_lt_, last_transaction_hash_), std::move(P));
}

void Wallet::got_last_transaction(lite_api_ptr<lite_api::liteServer_transactionList>&& transactions_list)
{
    LOG(DEBUG) << "got last transaction " << last_transaction_lt_ << ":" << last_transaction_hash_.to_hex();

    auto list_r = vm::std_boc_deserialize_multi(std::move(transactions_list->transactions_));
    if (list_r.is_error()) {
        return finish(list_r.move_as_error());
    }
    auto list = list_r.move_as_ok();

    if (list.empty()) {
        return finish(td::Status::Error("no transactions found"));
    }

    block::gen::Transaction::Record transaction;
    if (!tlb::unpack_cell_inexact(std::move(list[0]), transaction)) {
        return finish(td::Status::Error("failed to unpack transaction"));
    }

    if (auto in_msg_ref = transaction.r1.in_msg->prefetch_ref(); in_msg_ref.not_null() && in_msg_ref->get_hash() == message_hash_) {
        return finish(found_transaction(std::move(transaction)));
    }

    const auto all_transactions_found = transaction.prev_trans_lt == first_transaction_lt_ &&  //
                                        transaction.prev_trans_hash == first_transaction_hash_;

    if (all_transactions_found) {
        LOG(DEBUG) << "All transactions found";

        first_transaction_lt_ = last_transaction_lt_ = account_info_.last_trans_lt;
        first_transaction_hash_ = last_transaction_hash_ = account_info_.last_trans_hash;
        get_last_block_state();
    }
    else {
        last_transaction_lt_ = transaction.prev_trans_lt;
        last_transaction_hash_ = transaction.prev_trans_hash;
        get_last_transaction();
    }
}

auto Wallet::run_local() -> td::Status
{
    LOG(DEBUG) << "Run local";

    CHECK(mode_ == Mode::send_message)
    TRY_RESULT(encoded_message, context_->create_message())
    auto [function, state_init, body] = std::move(encoded_message);

    TRY_RESULT(output, ftabi::run_smc_method(addr_, std::move(account_info_), std::move(function), std::move(state_init), std::move(body)))
    return context_->handle_result(std::move(output));
}

auto Wallet::run_remote() -> td::Status
{
    LOG(DEBUG) << "Run remote";

    CHECK(mode_ == Mode::send_message)
    TRY_RESULT(encoded_message, context_->create_message())
    auto [function, state_init, body] = std::move(encoded_message);
    function_ = std::move(function);

    auto message = ton::GenericAccount::create_ext_message(addr_, state_init, body);
    expires_at_ = context_->expires_at();
    message_hash_ = message->get_hash();

    LOG(DEBUG) << "Message hash: " << message_hash_.to_hex();

    TRY_RESULT(serialized_message, vm::std_boc_serialize(std::move(message)))
    send_message(std::move(serialized_message));
    return td::Status::OK();
}

void Wallet::send_message(td::BufferSlice&& message)
{
    LOG(DEBUG) << "Send message";

    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_sendMsgStatus>> R) mutable {
        if (R.is_error()) {
            td::actor::send_closure(SelfId, &Wallet::finish, R.move_as_error());
        }
        else {
            td::actor::send_closure(SelfId, &Wallet::sent_message, R.move_as_ok());
        }
    });
    client_.send_query(lite_api::liteServer_sendMessage(std::move(message)), std::move(P));
}

void Wallet::sent_message(lite_api_ptr<lite_api::liteServer_sendMsgStatus>&& send_msg_status)
{
    LOG(DEBUG) << "Sent message";

    if (send_msg_status->status_ != 1) {
        return finish(td::Status::Error("failed to send message"));
    }

    state_ = State::waiting_transaction;
    get_last_block_state();
}

auto Wallet::found_transaction(block::gen::Transaction::Record&& transaction) -> td::Status
{
    LOG(DEBUG) << "Found transaction";

    if (transaction.outmsg_cnt == 0) {
        if (function_->has_output()) {
            return td::Status::Error("out messages missing");
        }
        else {
            return context_->handle_result({});
        }
    }

    vm::Dictionary dict{transaction.r1.out_msgs, 15};
    for (td::int32 i = 0; i < transaction.outmsg_cnt; ++i) {
        auto out_msg = dict.lookup_ref(td::BitArray<15>{i});

        auto msg_cs = vm::load_cell_slice(out_msg);
        if (msg_cs.prefetch_ulong(2) != 3) {
            continue;
        }

        TRY_RESULT(body, ftabi::unpack_result_message_body(msg_cs))
        const auto output_id = static_cast<uint32_t>(body->prefetch_ulong(32));
        if (function_->output_id() != output_id) {
            continue;
        }

        TRY_RESULT(output, function_->decode_output(std::move(std::move(body))))
        return context_->handle_result(std::move(output));
    }

    return td::Status::Error("no external output messages");
}

void Wallet::check(td::Status status)
{
    if (status.is_error()) {
        LOG(DEBUG) << status.message();
        switch (mode_) {
            case Mode::get_account_info:
                account_info_handler_.set_error(status.move_as_error());
                break;
            case Mode::send_message:
                context_->handle_error(status.move_as_error());
                break;
            default:
                CHECK(false)
        }
        stop();
    }
}

void Wallet::finish(td::Status status)
{
    check(status.move_as_error());
    stop();
}

}  // namespace app
