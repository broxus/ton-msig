#pragma once

#include <tonlib/Stuff.h>

namespace app
{
class Contract {
public:
    static auto generate_addr(const td::Ed25519::PublicKey& public_key) -> td::Result<ton::StdSmcAddress>;
    static auto generate_state_init(const td::Ed25519::PublicKey& public_key) -> td::Result<td::Ref<vm::Cell>>;

private:
};

}  // namespace app
