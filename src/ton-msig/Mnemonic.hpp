#pragma once

#include <crypto/Ed25519.h>

namespace app
{
auto recover_key(const std::string& mnemonic) -> td::Result<td::Ed25519::PrivateKey>;

}  // namespace app
