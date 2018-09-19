/// @brief Implements a simple branch proxy.
///
/// This proxy forwards all requests to the branch referring to the current process.

#include "klib/klib.h"
#include "processor/processor.h"
#include "system_tree/fs/proc/proc_fs.h"

proc_fs_root_branch::proc_fs_zero_proxy_branch::proc_fs_zero_proxy_branch(std::shared_ptr<proc_fs_root_branch> parent):
  _parent(std::weak_ptr<proc_fs_root_branch>(parent))
{
  ASSERT(parent != nullptr);
}

proc_fs_root_branch::proc_fs_zero_proxy_branch::~proc_fs_zero_proxy_branch()
{

}

ERR_CODE proc_fs_root_branch::proc_fs_zero_proxy_branch::get_child_type(const kl_string &name, CHILD_TYPE &type)
{
  return this->get_current_proc_branch()->get_child_type(name, type);
}

ERR_CODE proc_fs_root_branch::proc_fs_zero_proxy_branch::get_branch(const kl_string &name, 
                                                                    std::shared_ptr<ISystemTreeBranch> &branch)
{
  return this->get_current_proc_branch()->get_branch(name, branch);
}

ERR_CODE proc_fs_root_branch::proc_fs_zero_proxy_branch::get_leaf(const kl_string &name,
                                                                  std::shared_ptr<ISystemTreeLeaf> &leaf)
{
  return this->get_current_proc_branch()->get_leaf(name, leaf);
}

ERR_CODE proc_fs_root_branch::proc_fs_zero_proxy_branch::add_branch(const kl_string &name, 
                                                                    std::shared_ptr<ISystemTreeBranch> branch)
{
  return this->get_current_proc_branch()->add_branch(name, branch);
}

ERR_CODE proc_fs_root_branch::proc_fs_zero_proxy_branch::add_leaf(const kl_string &name, 
                                                                  std::shared_ptr<ISystemTreeLeaf> leaf)
{
  return this->get_current_proc_branch()->add_leaf(name, leaf);
}

ERR_CODE proc_fs_root_branch::proc_fs_zero_proxy_branch::rename_child(const kl_string &old_name,
                                                                      const kl_string &new_name)
{
  return this->get_current_proc_branch()->rename_child(old_name, new_name);
}

ERR_CODE proc_fs_root_branch::proc_fs_zero_proxy_branch::delete_child(const kl_string &name)
{
  return this->get_current_proc_branch()->delete_child(name);
}

std::shared_ptr<ISystemTreeBranch> proc_fs_root_branch::proc_fs_zero_proxy_branch::get_current_proc_branch()
{
  std::shared_ptr<ISystemTreeBranch> cur_proc_branch;
  std::shared_ptr<proc_fs_root_branch> parent_branch = _parent.lock();
  kl_string branch_name;
  char name_buffer[22];

  KL_TRC_ENTRY;

  task_thread *t = task_get_cur_thread();
  ASSERT(t != nullptr);
  ASSERT(t->parent_process != nullptr);

  klib_snprintf(name_buffer, 22, "%p", t->parent_process.get());
  branch_name = name_buffer;

  KL_TRC_TRACE(TRC_LVL::FLOW, "Retrieving branch: ", branch_name, "\n");

  // This is an if-statement because it's possible that I've forgotten a window condition somewhere. The panic will do
  // for now.
  if (parent_branch->get_branch(branch_name, cur_proc_branch) != ERR_CODE::NO_ERROR)
  {
    KL_TRC_TRACE(TRC_LVL::FLOW, "Branch doesn't exist???\n");
    panic("Current process branch not found");
  }

  KL_TRC_TRACE(TRC_LVL::EXTRA, "Return value: ", cur_proc_branch, "\n");
  KL_TRC_EXIT;

  return cur_proc_branch;
}

ERR_CODE proc_fs_root_branch::proc_fs_zero_proxy_branch::create_branch(const kl_string &name, 
                                                                       std::shared_ptr<ISystemTreeBranch> &branch)
{
  return this->get_current_proc_branch()->create_branch(name, branch);
}

ERR_CODE proc_fs_root_branch::proc_fs_zero_proxy_branch::create_leaf(const kl_string &name, 
                                                                     std::shared_ptr<ISystemTreeLeaf> &leaf)
{
  return this->get_current_proc_branch()->create_leaf(name, leaf);
}
