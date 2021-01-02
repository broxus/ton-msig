#pragma once

#include <crypto/Ed25519.h>

namespace app::mnemonic
{
auto recover_key(const std::string& mnemonic) -> td::Result<td::Ed25519::PrivateKey>;
auto generate_words() -> std::vector<td::SecureString>;
auto generate_phrase() -> td::SecureString;
auto generate_key(std::string& mnemonic) -> td::Result<td::Ed25519::PrivateKey>;

}  // namespace app::mnemonic
