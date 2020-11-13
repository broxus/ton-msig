#include "Contract.hpp"

#include <res/safe_multisig_wallet_tvc.h>

#include <ftabi/ftabi/utils.hpp>

namespace app
{
namespace
{
template <typename T, size_t N>
static auto load_slice(T (&data)[N]) -> td::Slice
{
    return td::Slice{reinterpret_cast<const char*>(data), N * sizeof(T)};
}

auto safe_multisig_wallet_tvc() -> td::Ref<vm::Cell>
{
    static td::Ref<vm::Cell> decoded{};
    if (decoded.is_null()) {
        decoded = vm::std_boc_deserialize(load_slice(SAFE_MULTISIG_WALLET_TVC)).move_as_ok();
    }
    return decoded;
}

}  // namespace

auto Contract::generate_addr(const td::Ed25519::PublicKey& public_key) -> td::Result<ton::StdSmcAddress>
{
    TRY_RESULT(state_init, generate_state_init(public_key))
    return state_init->get_hash().bits();
}

auto Contract::generate_state_init(const td::Ed25519::PublicKey& public_key) -> td::Result<td::Ref<vm::Cell>>
{
    return ftabi::generate_state_init(safe_multisig_wallet_tvc(), public_key);
}

}  // namespace app
