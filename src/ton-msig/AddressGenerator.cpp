#include "AddressGenerator.hpp"

#include <td/utils/port/thread_local.h>

#include <atomic>
#include <cppcodec/hex_lower.hpp>
#include <thread>

#include "Mnemonic.hpp"

namespace app
{
namespace
{
auto decode_target(const std::string& target) -> td::Result<td::Bits256>
{
    try {
        const auto decoded_target = cppcodec::hex_lower::decode(target);
        const auto target_size = std::min(decoded_target.size(), 32ul);

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

}  // namespace

auto generate_address(const std::string& target) -> td::Result<td::Unit>
{
    TRY_RESULT(target_bits, decode_target(target))
    LOG(WARNING) << "Target: " << target_bits.to_hex();

    auto thread_count = std::thread::hardware_concurrency();
    LOG(WARNING) << "Thread count " << thread_count;

    std::vector<td::thread> threads;
    threads.reserve(thread_count);

    int last_matching = 0;
    std::mutex output_mutex;
    for (size_t i = 0; i < thread_count; ++i) {
        threads.emplace_back(td::thread([&last_matching, &output_mutex, target_bits] {
            size_t current_iteration = 0;
            auto thread_id = td::get_thread_id();

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"
            while (true) {
                ++current_iteration;

                std::string new_phrase{};
                auto private_key = mnemonic::generate_key(new_phrase).move_as_ok();
                auto public_key = private_key.get_public_key().move_as_ok();

                auto address = Contract::generate_addr(public_key).move_as_ok();

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
        }));
    }

    for (auto&& thread : threads) {
        thread.join();
    }

    UNREACHABLE();
}

}  // namespace app
