#include "Action.hpp"

using namespace ftabi;

namespace app
{

auto empty_function_call() -> ftabi::FunctionCallRef
{
    static FunctionCallRef call{FunctionCall{{}}};
    return call;
}

}  // namespace app
