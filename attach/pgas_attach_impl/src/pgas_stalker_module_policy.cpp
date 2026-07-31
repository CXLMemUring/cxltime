// SPDX-License-Identifier: MIT
#include "pgas_stalker_module_policy.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <stdexcept>

namespace bpftime::attach {

namespace {

constexpr std::array<std::string_view, 9> hard_denied_modules{
    "libfrida-gum.so",
    "libpgas_preload.so",
    "libcxlmemsim_client.so",
    "libc.so.6",
    "libpthread.so.0",
    "libdl.so.2",
    "librt.so.1",
    "ld-linux-x86-64.so.2",
    "ld-linux-aarch64.so.1",
};

std::string_view trim(std::string_view value)
{
    while (!value.empty() &&
           std::isspace(static_cast<unsigned char>(value.front())))
        value.remove_prefix(1);
    while (!value.empty() &&
           std::isspace(static_cast<unsigned char>(value.back())))
        value.remove_suffix(1);
    return value;
}

bool is_hard_denied(std::string_view basename)
{
    return std::any_of(hard_denied_modules.begin(), hard_denied_modules.end(),
                       [basename](std::string_view module) {
                           return basename == module ||
                                  (basename.starts_with(module) &&
                                   basename.size() > module.size() &&
                                   basename[module.size()] == '.');
                       });
}

} // namespace

pgas_stalker_module_policy::pgas_stalker_module_policy(std::string_view csv)
{
    if (trim(csv).empty())
        return;

    size_t start = 0;
    while (start <= csv.size()) {
        const size_t comma = csv.find(',', start);
        const size_t length = comma == std::string_view::npos
                                  ? csv.size() - start
                                  : comma - start;
        const std::string_view entry = trim(csv.substr(start, length));
        if (entry.empty())
            throw std::invalid_argument("empty PGAS Stalker module entry");

        const std::string module(entry);
        if (std::find(requested_.begin(), requested_.end(), module) ==
            requested_.end())
            requested_.push_back(module);

        if (comma == std::string_view::npos)
            break;
        start = comma + 1;
    }
}

bool pgas_stalker_module_policy::should_instrument(std::string_view basename,
                                                   bool is_main)
{
    if (is_hard_denied(basename))
        return false;
    if (is_main)
        return true;

    std::lock_guard lock(mutex_);
    const auto requested =
        std::find(requested_.begin(), requested_.end(), basename);
    if (requested == requested_.end())
        return false;

    observed_.insert(*requested);
    return true;
}

std::vector<std::string>
pgas_stalker_module_policy::requested_but_unseen() const
{
    std::lock_guard lock(mutex_);
    std::vector<std::string> result;
    for (const auto &module : requested_) {
        if (!observed_.contains(module))
            result.push_back(module);
    }
    return result;
}

} // namespace bpftime::attach
