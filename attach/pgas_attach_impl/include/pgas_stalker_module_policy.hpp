// SPDX-License-Identifier: MIT
#pragma once

#include <mutex>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace bpftime::attach {

class pgas_stalker_module_policy {
  public:
    explicit pgas_stalker_module_policy(std::string_view csv);

    bool may_instrument(std::string_view basename, bool is_main) const;
    bool should_instrument(std::string_view basename, bool is_main);
    std::vector<std::string> requested_but_unseen() const;

  private:
    std::vector<std::string> requested_;
    std::unordered_set<std::string> observed_;
    mutable std::mutex mutex_;
};

} // namespace bpftime::attach
