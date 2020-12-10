#pragma once

#include "Contract.hpp"

namespace app
{
auto generate_address(const std::string& target) -> td::Result<td::Unit>;

}  // namespace app
