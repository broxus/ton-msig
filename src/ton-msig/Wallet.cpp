#include "Wallet.hpp"

#include <ton/lite-tl.hpp>

namespace app
{
void Wallet::start_up()
{
    if (context_->is_get_method()) {
        state_ = State::calling_method_local;
    }
    else {
        state_ = State::calling_method_remote;
        created_at_ = context_->created_at();
        expires_at_ = context_->expires_at();
    }
    get_last_block_state();
}

void Wallet::loop()
{
    LOG(WARNING) << "Loop called for state: " << static_cast<int>(state_);
    if (state_ == State::waiting_transaction_sleep) {
        state_ = State::waiting_transaction;
        get_last_block_state();
    }
}

void Wallet::get_last_block_state()
{
    LOG(WARNING) << "get last block state";
    auto last_block_handler = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_masterchainInfo>> R) {
        if (R.is_error()) {
            td::actor::send_closure(SelfId, &Wallet::check, R.move_as_error());
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

    LOG(WARNING) << "got last block state" << last_block_id_.to_str();

    get_account_state();
}

void Wallet::get_account_state()
{
    LOG(WARNING) << "get account state" << last_block_id_.to_str();

    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_accountState>> R) mutable {
        if (R.is_error()) {
            td::actor::send_closure(SelfId, &Wallet::check, R.move_as_error());
        }
        else {
            td::actor::send_closure(SelfId, &Wallet::got_account_state, R.move_as_ok());
        }
    });
    client_.send_query(lite_api::liteServer_getAccountState(ton::create_tl_lite_block_id(last_block_id_), to_lite_api(addr_)), std::move(P));
}

void Wallet::got_account_state(lite_api_ptr<lite_api::liteServer_accountState>&& account_state)
{
    LOG(WARNING) << "got account state" << last_block_id_.to_str();

    block::AccountState state;
    state.blk = ton::create_block_id(account_state->id_);
    state.shard_blk = ton::create_block_id(account_state->shardblk_);
    state.shard_proof = std::move(account_state->shard_proof_);
    state.proof = std::move(account_state->proof_);
    state.state = std::move(account_state->state_);
    auto info_r = state.validate(last_block_id_, block::StdAddress(addr_.workchain, addr_.addr));
    if (info_r.is_error()) {
        return check(info_r.move_as_error());
    }
    account_info_ = info_r.move_as_ok();

    if (account_info_.root.is_null()) {
        return check(td::Status::Error("account is empty"));
    }

    const auto still_same_transaction = last_transaction_lt_ == account_info_.last_trans_lt &&  //
                                        last_transaction_hash_ == account_info_.last_trans_hash;

    last_transaction_lt_ = account_info_.last_trans_lt;
    last_transaction_hash_ = account_info_.last_trans_hash;

    LOG(WARNING) << "previous transaction: " << last_transaction_lt_ << ":" << last_transaction_hash_.to_hex();

    switch (state_) {
        case State::calling_method_local: {
            return check(run_local());
        }
        case State::calling_method_remote: {
            first_transaction_lt_ = last_transaction_lt_;
            first_transaction_hash_ = last_transaction_hash_;
            return check(run_remote());
        }
        case State::waiting_transaction: {
            if (still_same_transaction && account_info_.gen_utime > expires_at_) {
                return check(td::Status::Error("message expired"));
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
            CHECK(false)
        }
    }
}

void Wallet::get_last_transaction()
{
    LOG(WARNING) << "get last transaction " << last_transaction_lt_ << ":" << last_transaction_hash_.to_hex();
    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_transactionList>> R) mutable {
        if (R.is_error()) {
            td::actor::send_closure(SelfId, &Wallet::check, R.move_as_error());
        }
        else {
            td::actor::send_closure(SelfId, &Wallet::got_last_transaction, R.move_as_ok());
        }
    });
    client_.send_query(lite_api::liteServer_getTransactions(1, to_lite_api(addr_), last_transaction_lt_, last_transaction_hash_), std::move(P));
}

void Wallet::got_last_transaction(lite_api_ptr<lite_api::liteServer_transactionList>&& transactions_list)
{
    LOG(WARNING) << "got last transaction " << last_transaction_lt_ << ":" << last_transaction_hash_.to_hex();

    auto list_r = vm::std_boc_deserialize_multi(std::move(transactions_list->transactions_));
    if (list_r.is_error()) {
        return check(list_r.move_as_error());
    }
    auto list = list_r.move_as_ok();

    if (list.empty()) {
        return check(td::Status::Error("no transactions found"));
    }

    block::gen::Transaction::Record transaction;
    if (!tlb::unpack_cell_inexact(std::move(list[0]), transaction)) {
        return check(td::Status::Error("failed to unpack transaction"));
    }

    if (auto in_msg_ref = transaction.r1.in_msg->prefetch_ref(); in_msg_ref.not_null() && in_msg_ref->get_hash() == message_hash_) {
        return check(found_transaction(std::move(transaction)));
    }

    const auto all_transactions_found = transaction.prev_trans_lt == first_transaction_lt_ &&  //
                                        transaction.prev_trans_hash == first_transaction_hash_;

    if (all_transactions_found) {
        LOG(WARNING) << "All transactions found";

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
    LOG(WARNING) << "Run local";

    CHECK(state_ == State::calling_method_local)
    TRY_RESULT(encoded_body, context_->create_body())
    TRY_RESULT(output, ftabi::run_smc_method(addr_, std::move(account_info_), std::move(encoded_body.first), std::move(encoded_body.second)))
    return context_->handle_result(std::move(output));
}

auto Wallet::run_remote() -> td::Status
{
    LOG(WARNING) << "Run remote";

    CHECK(state_ == State::calling_method_remote)
    TRY_RESULT(encoded_body, context_->create_body())
    function_ = std::move(encoded_body.first);

    auto message = ton::GenericAccount::create_ext_message(addr_, {}, encoded_body.second);
    message_hash_ = message->get_hash();

    vm::load_cell_slice(message).print_rec(std::cerr);

    LOG(WARNING) << "Message hash: " << message_hash_.to_hex();

    LOG(WARNING) << function_->output_id();

    TRY_RESULT(serialized_message, vm::std_boc_serialize(std::move(message)))
    send_message(std::move(serialized_message));
    return td::Status::OK();
}

void Wallet::send_message(td::BufferSlice&& message)
{
    LOG(WARNING) << "Send message";

    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_sendMsgStatus>> R) mutable {
        if (R.is_error()) {
            td::actor::send_closure(SelfId, &Wallet::check, R.move_as_error());
        }
        else {
            td::actor::send_closure(SelfId, &Wallet::sent_message, R.move_as_ok());
        }
    });
    client_.send_query(lite_api::liteServer_sendMessage(std::move(message)), std::move(P));
}

void Wallet::sent_message(lite_api_ptr<lite_api::liteServer_sendMsgStatus>&& send_msg_status)
{
    LOG(WARNING) << "Sent message";

    if (send_msg_status->status_ != 1) {
        return check(td::Status::Error("failed to send message"));
    }

    state_ = State::waiting_transaction;
    get_last_block_state();
}

auto Wallet::found_transaction(block::gen::Transaction::Record&& transaction) -> td::Status
{
    LOG(WARNING) << "Found transaction";

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
        LOG(ERROR) << status.message();
        context_->handle_error(status.move_as_error());
        stop();
    }
}

}  // namespace app
