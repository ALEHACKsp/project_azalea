#pragma once

#include "klib/panic/panic.h"
#include "klib/tracing/tracing.h"
#include "klib/misc/assert.h"

template <typename T> struct klib_list;

template <typename T> struct klib_list_item
{
	klib_list_item<T>* prev;
	T item;
	klib_list<T> *list_obj;
	klib_list_item<T> *next;
};

template <typename T> struct klib_list
{
	klib_list_item<T> *head;
	klib_list_item<T> *tail;
};

template <typename T> void klib_list_initialize(klib_list<T> *new_list)
{
  ASSERT(new_list != nullptr);
  new_list->head = nullptr;
  new_list->tail = nullptr;
}

template <typename T> void klib_list_item_initialize(klib_list_item<T> *new_item)
{
  ASSERT(new_item != nullptr);
  new_item->item = nullptr;
  new_item->list_obj = nullptr;
  new_item->next = nullptr;
  new_item->prev = nullptr;
}

template <typename T> void klib_list_add_after(klib_list_item<T> *list_item, klib_list_item<T> *new_item)
{
  ASSERT(list_item != nullptr);
  ASSERT(new_item != nullptr);
  ASSERT(new_item->list_obj == nullptr);
  ASSERT(new_item->item != nullptr);

  new_item->next = list_item->next;
  new_item->prev = list_item;
  list_item->next = new_item;
  if (new_item->next != nullptr)
  {
    new_item->next->prev = new_item;
  }
  new_item->list_obj = list_item->list_obj;

  if (list_item->list_obj->tail == list_item)
  {
    list_item->list_obj->tail = new_item;
  }
}

template <typename T> void klib_list_add_before(klib_list_item<T> *list_item, klib_list_item<T> *new_item)
{
  ASSERT(list_item != nullptr);
  ASSERT(new_item != nullptr);
  ASSERT(new_item->list_obj == nullptr);
  ASSERT(new_item->item != nullptr);

  new_item->prev = list_item->prev;
  new_item->next = list_item;
  list_item->prev = new_item;
  if (new_item->prev != nullptr)
  {
    new_item->prev->next = new_item;
  }
  new_item->list_obj = list_item->list_obj;

  if (list_item->list_obj->head == list_item)
  {
    list_item->list_obj->head = new_item;
  }
}

template <typename T> void klib_list_add_tail(klib_list<T> *existing_list, klib_list_item<T> *new_item)
{
  ASSERT(existing_list != nullptr);
  ASSERT(new_item != nullptr);
  ASSERT(new_item->item != nullptr);

  if (existing_list->tail == nullptr)
  {
    ASSERT(existing_list->head == nullptr);
    existing_list->head = new_item;
    existing_list->tail = new_item;
    ASSERT(new_item->next == nullptr);
    ASSERT(new_item->prev == nullptr);
  }
  else
  {
    existing_list->tail->next = new_item;
    new_item->prev = existing_list->tail;
    existing_list->tail = new_item;
    ASSERT(new_item->next == nullptr);
  }

  new_item->list_obj = existing_list;
}

template <typename T> void klib_list_add_head(klib_list<T> *existing_list, klib_list_item<T> *new_item)
{
  ASSERT(existing_list != nullptr);
  ASSERT(new_item != nullptr);
  ASSERT(new_item->item != nullptr);

  if (existing_list->head == nullptr)
  {
    ASSERT(existing_list->tail == nullptr);
    existing_list->head = new_item;
    existing_list->tail = new_item;
    ASSERT(new_item->next == nullptr);
    ASSERT(new_item->prev == nullptr);
  }
  else
  {
    existing_list->head->prev = new_item;
    new_item->next = existing_list->head;
    existing_list->head = new_item;
    ASSERT(new_item->prev == nullptr);
  }

  new_item->list_obj = existing_list;
}

template <typename T> void klib_list_remove(klib_list_item<T> *entry_to_remove)
{
  ASSERT(entry_to_remove != nullptr);
  ASSERT(entry_to_remove->list_obj != nullptr);

  klib_list<T> *list_removing_from = entry_to_remove->list_obj;

  if (entry_to_remove->prev == nullptr)
  {
    ASSERT(list_removing_from->head == entry_to_remove);
    list_removing_from->head = entry_to_remove->next;
  }
  if (entry_to_remove->next == nullptr)
  {
    ASSERT(list_removing_from->tail == entry_to_remove);
    list_removing_from->tail = entry_to_remove->prev;
  }

  if (entry_to_remove->prev != nullptr)
  {
    entry_to_remove->prev->next = entry_to_remove->next;
  }
  if (entry_to_remove->next != nullptr)
  {
    entry_to_remove->next->prev = entry_to_remove->prev;
  }

  entry_to_remove->list_obj = nullptr;
  entry_to_remove->next = nullptr;
  entry_to_remove->prev = nullptr;
}

template <typename T> uint64_t klib_list_get_length(klib_list<T> *list_obj)
{
  uint64_t count = 0;
  klib_list_item<T> *list_item;

  ASSERT(list_obj != nullptr);
  list_item = list_obj->head;

  while(list_item != nullptr)
  {
    list_item = list_item->next;
    count++;
  }

  return count;
}

template <typename T> bool klib_list_is_valid(klib_list<T> *list_obj)
{
  ASSERT (list_obj != nullptr);
  klib_list_item<T> *cur_item;

  // If there's a list head, there must be a list tail.
  if (((list_obj->head == nullptr) && (list_obj->tail != nullptr)) ||
      ((list_obj->head != nullptr) && (list_obj->tail == nullptr)))
  {
    return false;
  }

  cur_item = list_obj->head;
  while (cur_item != nullptr)
  {
    // The item must believe that it's part of the list we're checking.
    if (cur_item->list_obj != list_obj)
    {
      return false;
    }

    // The only item that can have no previous item must be the list's head.
    if ((cur_item->prev == nullptr) && (list_obj->head != cur_item))
    {
      return false;
    }
    // The previous item must point at this one.
    else if ((cur_item->prev != nullptr) && (cur_item->prev->next != cur_item))
    {
      return false;
    }

    // Similarly for the tail.
    if ((cur_item->next == nullptr) && (list_obj->tail != cur_item))
    {
      return false;
    }
    else if ((cur_item->next != nullptr) && (cur_item->next->prev != cur_item))
    {
      return false;
    }

    // The list item must point at a valid object.
    if (cur_item->item == nullptr)
    {
      return false;
    }

    cur_item = cur_item->next;
  }

  return true;
}

template <typename T> bool klib_list_is_empty(klib_list<T> *list_obj)
{
  ASSERT(list_obj != nullptr);
  return ((list_obj->head == nullptr) && (list_obj->tail == nullptr));
}

template <typename T> bool klib_list_item_is_in_any_list(klib_list_item<T> *list_item_obj)
{
  ASSERT(list_item_obj != nullptr);
  return (list_item_obj->list_obj != nullptr);
}