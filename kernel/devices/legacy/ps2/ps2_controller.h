#ifndef DEVICE_PS2_CONTROLLER_HEADER
#define DEVICE_PS2_CONTROLLER_HEADER

#include "devices/device_interface.h"
#include "user_interfaces/error_codes.h"
#include "klib/data_structures/string.h"
#include "devices/legacy/ps2/ps2_device.h"

const uint16_t PS2_DATA_PORT = 0x60;
const uint16_t PS2_COMMAND_PORT = 0x64;

enum class PS2_DEV_TYPE
{
  NONE_CONNECTED,
  UNKNOWN,

  MOUSE_STANDARD,
  MOUSE_WITH_WHEEL,
  MOUSE_5_BUTTON,

  KEYBOARD_MF2,
};

// Constants useful to any PS/2 device.
namespace PS2_CONST
{
  // Controller command and response constants.
  const uint8_t READ_CONFIG = 0x20;
  const uint8_t WRITE_CONFIG = 0x60;
  const uint8_t SELF_TEST = 0xAA;
  const uint8_t SELF_TEST_SUCCESS = 0x55;
  const uint8_t DEV_1_PORT_TEST = 0xAB;
  const uint8_t DEV_2_PORT_TEST = 0xA9;

  const uint8_t PORT_TEST_SUCCESS = 0x00;

  const uint8_t DISABLE_DEV_1 = 0xAD;
  const uint8_t ENABLE_DEV_1 = 0xAE;

  const uint8_t DISABLE_DEV_2 = 0xA7;
  const uint8_t ENABLE_DEV_2 = 0xA8;

  const uint8_t DEV_2_NEXT = 0xD4;

  // General device command and response constants.
  const uint8_t DEV_RESET = 0xFF;
  const uint8_t DEV_IDENTIFY = 0xF2;
  const uint8_t DEV_ENABLE_SCANNING = 0xF4;
  const uint8_t DEV_DISABLE_SCANNING = 0xF5;
  const uint8_t DEV_CMD_ACK = 0xFA;
  const uint8_t DEV_CMD_RESEND = 0xFE;
  const uint8_t DEV_CMD_FAILED = 0xFC;

  const uint8_t DEV_SELF_TEST_OK = 0xAA;
}

class gen_ps2_controller_device: public IDevice
{
public:
  // Generic device management functions.
  gen_ps2_controller_device();
  virtual ~gen_ps2_controller_device();

  virtual const kl_string device_name();
  virtual DEV_STATUS get_device_status();

  // Types used throughout.
  union ps2_status_register
  {
    struct
    {
      uint8_t output_buffer_status :1; // 0 = no data waiting, 1 = data waiting.
      uint8_t input_buffer_status :1; // 1 = data waiting to transmit, 0 = no data waiting.
      uint8_t system_flag :1;
      uint8_t command_data_flag :1;
      uint8_t keyboard_lock :1;           // This field is system specific, but is apparently most commonly this.
      uint8_t device_two_out_buf_full :1; // This field is system specific, but is apparently most commonly this.
      uint8_t timeout_error :1;
      uint8_t parity_error :1;
    } flags;
    uint8_t raw;
  };

  union ps2_config_register
  {
    struct
    {
      uint8_t first_port_interrupt_enabled :1; // 1 = enabled, 0 = disabled.
      uint8_t second_port_interrupt_enabled :1; // As above.
      uint8_t system_flag :1; // Should always be set to 1.
      uint8_t zero_flag :1; // Should always be set to zero.
      uint8_t first_port_clock_disable :1; // 1 = clock disabled, 0 = enabled.
      uint8_t second_port_clock_disable :1; // As above.
      uint8_t first_port_translation :1; // 1 = translation enabled.
      uint8_t second_zero_flag :1; // Must be zero.
    } flags;
    uint8_t raw;
  };

  // PS/2 device interactions.
  ERR_CODE send_ps2_command(uint8_t command,
                            bool needs_second_byte,
                            uint8_t second_byte,
                            bool expect_response,
                            uint8_t &response);

  ps2_status_register read_status();

  ps2_config_register read_config();
  void write_config(ps2_config_register reg);

  ERR_CODE send_byte(uint8_t data, bool second_channel = false);
  ERR_CODE read_byte(uint8_t &data);

  gen_ps2_device *chan_1_dev;
  gen_ps2_device *chan_2_dev;


protected:
  const kl_string _name;
  DEV_STATUS _status;
  bool _dual_channel;

  PS2_DEV_TYPE _chan_1_dev_type;
  PS2_DEV_TYPE _chan_2_dev_type;

  PS2_DEV_TYPE identify_device(bool second_channel);
  gen_ps2_device *instantiate_device(bool second_channel, PS2_DEV_TYPE dev_type);
};

static_assert(sizeof(gen_ps2_controller_device::ps2_status_register) == 1, "Incorrect packing of ps2_status_register");
static_assert(sizeof(gen_ps2_controller_device::ps2_config_register) == 1, "Incorrect packing of ps2_config_register");

#endif