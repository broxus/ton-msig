#pragma once

#include <tonlib/Stuff.h>

namespace app
{
enum class ContractType { SafeMultisigWallet, SafeMultisigWallet24h, SetcodeMultisigWallet, Surf };

auto generate_addr(ContractType contract_type, const td::Ed25519::PublicKey& public_key) -> td::Result<ton::StdSmcAddress>;
auto generate_state_init(ContractType contract_type, const td::Ed25519::PublicKey& public_key) -> td::Result<td::Ref<vm::Cell>>;
auto mine_pretty_addr(ContractType contract_type, const std::string& target) -> td::Result<td::Unit>;

}  // namespace app
