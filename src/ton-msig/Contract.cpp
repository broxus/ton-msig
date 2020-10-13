#include "Contract.hpp"

#include <res/safe_multisig_wallet_tvc.h>

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
    block::gen::StateInit::Record state_init;
    if (!tlb::unpack_cell(safe_multisig_wallet_tvc(), state_init)) {
        return td::Status::Error("Failed to unpack state_init");
    }

    vm::CellBuilder value_cb{};
    if (!value_cb.store_bytes_bool(public_key.as_octet_string())) {
        return td::Status::Error("Failed to create public key value");
    }

    try {
        auto data = vm::load_cell_slice_ref(state_init.data->prefetch_ref());
        vm::Dictionary map{data, 64};
        td::BitArray<64> key{};
        map.set(key, value_cb.as_cellslice_ref(), vm::Dictionary::SetMode::Replace);

        value_cb.reset();
        auto packed_map = value_cb.store_ones(1).store_ref(map.get_root_cell()).finalize();
        state_init.data = value_cb.store_ones(1).store_ref(packed_map).as_cellslice_ref();
    }
    catch (const vm::VmError& e) {
        return td::Status::Error(PSLICE() << "VM error: " << e.as_status().message());
    }

    td::Ref<vm::Cell> new_state;
    if (!tlb::pack_cell(new_state, state_init)) {
        return td::Status::Error("Failed to pack state_init");
    }

    return new_state;
}

}  // namespace app
