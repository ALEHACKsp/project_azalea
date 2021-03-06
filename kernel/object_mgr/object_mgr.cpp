/// @file
/// @brief Kernel's Object Manager
///
/// The Object Manager correlates handles and objects. Objects are any data object the user wishes to keep a reference
/// to. Users are responsible for ensuring that objects are removed from the Object Manager before destruction. The
/// kernel has several instances of OM objects - each thread has one, since handles are unique to each thread.
///
/// When an object is said to be "stored in OM" it does not mean that the object is in any way copied into OM. OM
/// simply stores a reference to the object (a pointer at the moment) which continues to live where it did before.
///
/// Handles within OM are unique to a thread - attempting to use a handle in a thread other than the one it was
/// correlated in will cause the object lookup to fail.

#include "klib/klib.h"
#include "handles.h"
#include "object_mgr.h"
#include "processor/processor.h"

/// @brief Initialise the object manager system
object_manager::object_manager()
{
  KL_TRC_ENTRY;

  klib_synch_spinlock_init(om_main_lock);

  KL_TRC_EXIT;
}

object_manager::~object_manager()
{
}

/// @brief Store an object in Object Manager
///
/// Stores an object in Object Manager and returns a new handle to reference it by.
///
/// @param object_ptr A pointer to the object to store in OM
///
/// @return A handle that correlates to object_ptr
GEN_HANDLE object_manager::store_object(std::shared_ptr<IHandledObject> object_ptr)
{
  KL_TRC_ENTRY;

  GEN_HANDLE new_handle = hm_get_handle();

  ASSERT(object_ptr != nullptr);

  this->correlate_object(object_ptr, new_handle);

  KL_TRC_TRACE(TRC_LVL::EXTRA, "New handle: ", new_handle, "\n");
  KL_TRC_EXIT;

  return new_handle;
}

/// @brief Store an object in Object Manager with a known handle
///
/// In some cases, it is useful for the caller to have generated a handle for an object it wishes to store in OM. This
/// function stores the object and correlates it with the provided handle.
///
/// @param object_ptr A pointer to the object to be stored
///
/// @param handle The handle that should refer to object_ptr
void object_manager::correlate_object(std::shared_ptr<IHandledObject> object_ptr, GEN_HANDLE handle)
{
  KL_TRC_ENTRY;

  std::shared_ptr<object_data> new_object = std::make_shared<object_data>();

  KL_TRC_TRACE(TRC_LVL::EXTRA, "Object pointer: ", object_ptr, "\n");

  ASSERT(object_ptr != nullptr);

  new_object->object_ptr = object_ptr;
  new_object->handle = handle;

  klib_synch_spinlock_lock(om_main_lock);
  object_store.insert(handle, new_object);
  klib_synch_spinlock_unlock(om_main_lock);

  KL_TRC_EXIT;
}

/// @brief Retrieve the object that correlates to handle
///
/// @param handle The handle to retrieve the corresponding object for
///
/// @return A pointer to the object stored in OM. nullptr if the handle does not correspond to an object in OM.
std::shared_ptr<IHandledObject> object_manager::retrieve_object(GEN_HANDLE handle)
{
  KL_TRC_ENTRY;

  std::shared_ptr<object_data> found_object;
  std::shared_ptr<IHandledObject> object_ptr;

  KL_TRC_TRACE(TRC_LVL::EXTRA, "Looking for handle ", handle, "\n");

  klib_synch_spinlock_lock(om_main_lock);
  found_object = this->int_retrieve_object(handle);
  klib_synch_spinlock_unlock(om_main_lock);

  if (found_object != nullptr)
  {
    KL_TRC_TRACE(TRC_LVL::EXTRA, "Found object", found_object->object_ptr, "\n");
    object_ptr = found_object->object_ptr;
  }
  else
  {
    KL_TRC_TRACE(TRC_LVL::FLOW, "Didn't find object\n");
    object_ptr = nullptr;
  }
  KL_TRC_EXIT;
  return object_ptr;
}

/// @brief Remove an object from OM and destroy the handle
///
/// Removes the correlation between a handle and object, and frees the handle for re-use. It is up to the caller to
/// manage the lifetime of the associated object.
///
/// @param handle The handle to destroy
void object_manager::remove_object(GEN_HANDLE handle)
{
  KL_TRC_ENTRY;

  KL_TRC_TRACE(TRC_LVL::EXTRA, "Remove and destroy handle ", handle, "\n");
  this->decorrelate_object(handle);
  hm_release_handle(handle);

  KL_TRC_EXIT;
}

/// @brief Remove the correlation between handle and object, but leave both intact
///
/// Removes the correlation between a handle and object, but does not deallocate the handle It is up to the caller to
/// manage the lifetime of both the object and handle.
///
/// This function will fail and panic if the correlation is not legitimate.
///
/// @param handle The handle for the object to remove.
void object_manager::decorrelate_object(GEN_HANDLE handle)
{
  KL_TRC_ENTRY;

  std::shared_ptr<object_data> found_object;

  KL_TRC_TRACE(TRC_LVL::EXTRA, "Removing object with handle ", handle, "\n");

  klib_synch_spinlock_lock(om_main_lock);
  found_object = this->int_retrieve_object(handle);
  object_store.remove(handle);
  klib_synch_spinlock_unlock(om_main_lock);

  KL_TRC_EXIT;
}

/// @brief Retrieve all object data from OM
///
/// This function is internal to OM. It retrieves the underlying data structure storing a given object in OM. This
/// function contains no locking - **appropriate serialisation MUST be used**, only one function can call this one at
/// a time.
///
/// This function does not check that the handle is valid in this thread, that is up to the caller.
///
/// @param handle The handle to retrieve data for
///
/// @return The underlying object data in OM.
std::shared_ptr<object_data> object_manager::int_retrieve_object(GEN_HANDLE handle)
{
  KL_TRC_ENTRY;

  std::shared_ptr<object_data> found_object;

  KL_TRC_TRACE(TRC_LVL::EXTRA, "Handle to retrieve: ", handle, "\n");

  if (object_store.contains(handle))
  {
    KL_TRC_TRACE(TRC_LVL::FLOW, "Object exists.\n");
    found_object = object_store.search(handle);
  }

  KL_TRC_TRACE(TRC_LVL::EXTRA, "Found item: ", found_object, "\n");
  KL_TRC_EXIT;

  return found_object;
}

void object_manager::remove_all_objects()
{
  KL_TRC_ENTRY;
  GEN_HANDLE root_handle;

  while (object_store.get_root_node_key(root_handle))
  {
    remove_object(root_handle);
  }

  KL_TRC_EXIT;
}