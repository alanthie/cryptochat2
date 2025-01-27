//-------------------------------------------------------------------
//  Learn tool
//  https://github.com/...
//  Created:     2018...
//  Copyright (C) 2018 ...
//-------------------------------------------------------------------

#ifndef __LEARN_TOOL_VERSION_H__
#define __LEARN_TOOL_VERSION_H__

namespace learntool
{

struct version final
{
    static constexpr int major() noexcept
    {
        return 1;
    }

    static constexpr int minor() noexcept
    {
        return 1;
    }

    static constexpr int patch() noexcept
    {
        return 0;
    }

    static constexpr char const* get_as_string() noexcept
    {
        return "1.1.0";
    }
};

} // namespace learntool

#endif // !__LEARN_TOOL_VERSION_H__

