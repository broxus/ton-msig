#include "AddressGenerator.hpp"

#include <res/safe_multisig_wallet_24h_tvc.h>
#include <res/safe_multisig_wallet_tvc.h>
#include <res/setcode_multisig_wallet_tvc.h>
#include <res/surf_tvc.h>
#include <td/utils/port/thread_local.h>

#include <atomic>
#include <cppcodec/hex_lower.hpp>
#include <ftabi/ftabi/utils.hpp>
#include <thread>

#include "Mnemonic.hpp"

namespace app
{
namespace
{
template <typename T, size_t N>
static auto load_slice(T (&data)[N]) -> td::Slice
{
    return td::Slice{reinterpret_cast<const char*>(data), N * sizeof(T)};
}

auto contract_tvc(ContractType contract_type) -> td::Ref<vm::Cell>
{
    static td::Ref<vm::Cell> decoded[4];

    const auto index = static_cast<int>(contract_type);
    if (decoded[index].is_null()) {
        td::Slice data{};
        switch (contract_type) {
            case ContractType::SafeMultisigWallet: {
                data = load_slice(SAFE_MULTISIG_WALLET_TVC);
                break;
            }
            case ContractType::SafeMultisigWallet24h: {
                data = load_slice(SAFE_MULTISIG_WALLET_24H_TVC);
                break;
            }
            case ContractType::SetcodeMultisigWallet: {
                data = load_slice(SETCODE_MULTISIG_WALLET_TVC);
                break;
            }
            case ContractType::Surf: {
                data = load_slice(SURF_TVC);
                break;
            }
        }
        decoded[index] = vm::std_boc_deserialize(data).move_as_ok();
    }
    return decoded[index];
}

auto decode_target(const std::string& target) -> td::Result<td::Bits256>
{
    try {
        const auto decoded_target = cppcodec::hex_lower::decode(target);
        const auto target_size = std::min(decoded_target.size(), size_t{32});

        td::Bits256 target_bits = td::Bits256::zero();
        if (target_size > 0) {
            target_bits.as_slice().copy_from(td::Slice{decoded_target.data(), target_size});
        }

        return target_bits;
    }
    catch (const cppcodec::parse_error& e) {
        return td::Status::Error(td::Slice(e.what()));
    }
}

void worker(ContractType contract_type, unsigned int& last_matching, std::mutex& output_mutex, td::Bits256 target_bits)
{
    size_t current_iteration = 0;
    auto thread_id = td::get_thread_id();

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"
    while (true) {
        ++current_iteration;

        std::string new_phrase{};
        auto private_key = mnemonic::generate_key(new_phrase).move_as_ok();
        auto public_key = private_key.get_public_key().move_as_ok();

        auto address = generate_addr(contract_type, public_key).move_as_ok();

        if (const auto current_matching = address.count_matching(target_bits); current_matching > last_matching) {
            last_matching = current_matching;

            output_mutex.lock();
            std::cout << "Found better addr (" << current_matching << " bits matched, thread " << thread_id << ", local iteration " << current_iteration
                      << ")\n"                             //
                      << "Phrase: " << new_phrase << "\n"  //
                      << "Addr: " << address.to_hex() << "\n"
                      << std::endl;
            output_mutex.unlock();
        }
    }
#pragma clang diagnostic pop
}

}  // namespace

auto mine_pretty_addr(ContractType contract_type, const std::string& target) -> td::Result<td::Unit>
{
    TRY_RESULT(target_bits, decode_target(target))
    LOG(WARNING) << "Target: " << target_bits.to_hex();

    auto thread_count = std::thread::hardware_concurrency();
    LOG(WARNING) << "Thread count " << thread_count;

    std::vector<td::thread> threads;
    threads.reserve(thread_count);

    unsigned int last_matching = 0;
    std::mutex output_mutex;
    for (size_t i = 0; i < thread_count; ++i) {
        threads.emplace_back(td::thread(  //
            [contract_type, &last_matching, &output_mutex, target_bits] { worker(contract_type, last_matching, output_mutex, target_bits); }));
    }

    for (auto&& thread : threads) {
        thread.join();
    }

    UNREACHABLE();
}

auto generate_addr(ContractType contract_type, const td::Ed25519::PublicKey& public_key) -> td::Result<ton::StdSmcAddress>
{
    TRY_RESULT(state_init, generate_state_init(contract_type, public_key))
    return state_init->get_hash().bits();
}

auto generate_state_init(ContractType contract_type, const td::Ed25519::PublicKey& public_key) -> td::Result<td::Ref<vm::Cell>>
{
    return ftabi::generate_state_init(contract_tvc(contract_type), public_key);
}

}  // namespace app
