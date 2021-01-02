#pragma once

#include <tonlib/Stuff.h>

namespace app
{
auto generate_addr(const td::Ed25519::PublicKey& public_key) -> td::Result<ton::StdSmcAddress>;
auto generate_state_init(const td::Ed25519::PublicKey& public_key) -> td::Result<td::Ref<vm::Cell>>;
auto mine_pretty_addr(const std::string& target) -> td::Result<td::Unit>;

}  // namespace app
