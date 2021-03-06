#ifndef _GEN_KEYBOARD_HDR
#define _GEN_KEYBOARD_HDR

#include <stdint.h>

#include "user_interfaces/keyboard.h"

/// @brief The properties of a single keyboard key
///
/// These structures are combined into a list of key properties for each scancode of a keyboard, so that key presses
/// can be converted in to actual input.
struct key_props
{
  bool printable;
  char normal;
  char shifted;
};

key_props keyb_get_key_props(KEYS key_pressed, key_props *key_props_table, uint32_t tab_len);
char keyb_translate_key(KEYS key_pressed, special_keys modifiers, key_props *key_props_table, uint32_t tab_len);

#endif