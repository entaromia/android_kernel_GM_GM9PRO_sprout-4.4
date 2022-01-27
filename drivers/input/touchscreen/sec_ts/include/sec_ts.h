/* drivers/input/touchscreen/sec_ts.h
 *
 * Copyright (C) 2015 Samsung Electronics Co., Ltd.
 * http://www.samsungsemi.com/
 *
 * Core file for Samsung TSC driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __SEC_TS_H__
#define __SEC_TS_H__

#include <asm/unaligned.h>
#include <linux/completion.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/hrtimer.h>
#include <linux/i2c.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_gpio.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/wakelock.h>

#ifdef CONFIG_SECURE_TOUCH
#include <linux/atomic.h>
#include <linux/clk.h>
#include <linux/pm_runtime.h>
#include <soc/qcom/scm.h>

#ifdef CONFIG_FB
#include <linux/notifier.h>
#include <linux/fb.h>
#endif

#define SECURE_TOUCH_ENABLE	1
#define SECURE_TOUCH_DISABLE	0
#define TZ_BLSP_MODIFY_OWNERSHIP_ID 3
#endif

#define USE_OPEN_CLOSE
#define MINORITY_REPORT

#define SEC_TS_I2C_NAME		"sec_ts"
#define SEC_TS_DEVICE_NAME	"SEC_TS"

/* support feature */
#define TYPE_STATUS_EVENT_ERR		1
#define TYPE_STATUS_EVENT_INFO		2
#define TYPE_STATUS_EVENT_VENDOR_INFO	7

#define BIT_STATUS_EVENT_ERR(a)		(a << TYPE_STATUS_EVENT_ERR)
#define BIT_STATUS_EVENT_INFO(a)	(a << TYPE_STATUS_EVENT_INFO)
#define BIT_STATUS_EVENT_VENDOR_INFO(a)	(a << TYPE_STATUS_EVENT_VENDOR_INFO)

#define MAX_SUPPORT_TOUCH_COUNT		10

#define SEC_TS_SELFTEST_REPORT_SIZE	80

#define I2C_WRITE_BUFFER_SIZE		(256 - 1)//10

#define SEC_TS_NVM_OFFSET_FAC_RESULT		0
#define SEC_TS_NVM_OFFSET_CAL_COUNT		1

/* SEC_TS READ REGISTER ADDRESS */
#define SEC_TS_CMD_SENSE_ON			0x10
#define SEC_TS_CMD_SENSE_OFF			0x11

#define SEC_TS_READ_FIRMWARE_INTEGRITY		0x21
#define SEC_TS_READ_DEVICE_ID			0x22
#define SEC_TS_READ_PANEL_INFO			0x23

#define SEC_TS_CMD_SET_TOUCHFUNCTION		0x30
#define SEC_TS_READ_ID				0x52
#define SEC_TS_READ_BOOT_STATUS			0x55
#define SEC_TS_READ_ONE_EVENT			0x60
#define SEC_TS_READ_ALL_EVENT			0x61
#define SEC_TS_CMD_CLEAR_EVENT_STACK		0x62
#define SEC_TS_CMD_MUTU_RAW_TYPE		0x70
#define SEC_TS_CMD_SELF_RAW_TYPE		0x71
#define SEC_TS_READ_TOUCH_RAWDATA		0x72
#define SEC_TS_READ_TOUCH_SELF_RAWDATA		0x73
#define SEC_TS_READ_SELFTEST_RESULT		0x80
#define SEC_TS_CMD_NVM				0x85
#define SEC_TS_CMD_STATEMANAGE_ON		0x8E

#define SEC_TS_CMD_STATUS_EVENT_TYPE	0xA0
#define SEC_TS_CMD_GET_CHECKSUM		0xA6
#define SEC_TS_READ_TS_STATUS		0xAF
#define SEC_TS_CMD_SELFTEST		0xAE

/* SEC_TS FLASH COMMAND */
#define SEC_TS_CMD_CHG_SYSMODE		0xD7

#define SEC_TS_CMD_SET_POWER_MODE	0xE4

#define SEC_TS_READ_CALIBRATION_REPORT		0xF1

#define SEC_TS_STATUS_BOOT_MODE		0x10

/* SEC status event id */
#define SEC_TS_COORDINATE_EVENT		0
#define SEC_TS_STATUS_EVENT		1

#define SEC_TS_EVENT_BUFF_SIZE		8

#define SEC_TS_COORDINATE_ACTION_NONE		0
#define SEC_TS_COORDINATE_ACTION_PRESS		1
#define SEC_TS_COORDINATE_ACTION_MOVE		2
#define SEC_TS_COORDINATE_ACTION_RELEASE	3

#define SEC_TS_TOUCHTYPE_NORMAL		0
#define SEC_TS_TOUCHTYPE_GLOVE		3
#define SEC_TS_TOUCHTYPE_PALM		5
#define SEC_TS_TOUCHTYPE_WET		6

/* SEC_TS_INFO : Info acknowledge event */
#define SEC_TS_ACK_BOOT_COMPLETE	0x00
#define SEC_TS_ACK_WET_MODE	0x1

/* SEC_TS_VENDOR_INFO : Vendor acknowledge event */
#define SEC_TS_VENDOR_ACK_SELF_TEST_DONE		0x41
#define SEC_TS_VENDOR_ACK_NOISE_STATUS_NOTI		0x64

/* SEC_TS_ERROR : Error event */
#define SEC_TS_ERR_EVENT_QUEUE_FULL	0x01

#define SEC_TS_BIT_SETFUNC_TOUCH		(1 << 0)
#define SEC_TS_BIT_SETFUNC_GLOVE		(1 << 3)
#define SEC_TS_BIT_SETFUNC_PALM			(1 << 5)
#define SEC_TS_BIT_SETFUNC_WET			(1 << 6)

#define SEC_TS_DEFAULT_ENABLE_BIT_SETFUNC	(SEC_TS_BIT_SETFUNC_TOUCH | SEC_TS_BIT_SETFUNC_PALM | SEC_TS_BIT_SETFUNC_WET)

#define STATE_MANAGE_ON			1
#define STATE_MANAGE_OFF		0

#define SEC_TS_CM_SPEC_OUT_RX_NODE		(1 << 0)
#define SEC_TS_CM_SPEC_OUT_TX_NODE		(1 << 1)
#define SEC_TS_CM_SPEC_OUT_RX_AVG		(1 << 2)
#define SEC_TS_CM_SPEC_OUT_TX_AVG		(1 << 3)

#define SEC_TS_I2C_RETRY_CNT		3
#define SEC_TS_WAIT_RETRY_CNT		100

#ifdef CONFIG_SEC_TS_WAKE_GESTURES
#define WG_PWRKEY_DUR   60

#define DT2W_FEATHER	150
#define DT2W_TIME 		300

#define TRIGGER_TIMEOUT	500
#endif

typedef enum {
	SEC_TS_STATE_POWER_OFF = 0,
	SEC_TS_STATE_POWER_ON
} TOUCH_POWER_MODE;

typedef enum {
	TOUCH_SYSTEM_MODE_TOUCH		= 2,
} TOUCH_SYSTEM_MODE;

typedef enum {
	TOUCH_MODE_STATE_TOUCH		= 2,
} TOUCH_MODE_STATE;

enum switch_system_mode {
	TO_TOUCH_MODE			= 0,
};

#ifdef CONFIG_SECURE_TOUCH
enum subsystem {
	TZ = 1,
	APSS = 3
};
#endif

enum {
	TYPE_RAW_DATA			= 0,	/* Total - Offset : delta data */
	TYPE_SIGNAL_DATA		= 1,	/* Signal - Filtering & Normalization */
	TYPE_AMBIENT_BASELINE	= 2,	/* Cap Baseline */
	TYPE_AMBIENT_DATA		= 3,	/* Cap Ambient */
	TYPE_REMV_BASELINE_DATA	= 4,
	TYPE_DECODED_DATA		= 5,	/* Raw */
	TYPE_REMV_AMB_DATA		= 6,	/*  TYPE_RAW_DATA - TYPE_AMBIENT_DATA */
	TYPE_OFFSET_DATA_SEC	= 19,	/* Cap Offset in SEC Manufacturing Line */
	TYPE_OFFSET_DATA_SDC	= 29,	/* Cap Offset in SDC Manufacturing Line */
	TYPE_RAWDATA_MAX,
	TYPE_INVALID_DATA		= 0xFF,	/* Invalid data type for release factory mode */
};

/* 8 byte */
struct sec_ts_event_status {
	u8 eid:2;
	u8 stype:4;
	u8 sf:2;
	u8 status_id;
	u8 status_data_1;
	u8 status_data_2;
	u8 status_data_3;
	u8 status_data_4;
	u8 status_data_5;
	u8 left_event_5_0:6;
	u8 reserved_2:2;
} __attribute__ ((packed));

/* 8 byte */
struct sec_ts_event_coordinate {
	u8 eid:2;
	u8 tid:4;
	u8 tchsta:2;
	u8 x_11_4;
	u8 y_11_4;
	u8 y_3_0:4;
	u8 x_3_0:4;
	u8 major;
	u8 minor;
	u8 z:6;
	u8 ttype_3_2:2;
	u8 left_event:6;
	u8 ttype_1_0:2;
} __attribute__ ((packed));

/* not fixed */
struct sec_ts_coordinate {
	u8 id;
	u8 ttype;
	u8 action;
	u16 x;
	u16 y;
	u8 z;
	u8 glove_flag;
	u8 touch_height;
	u16 mcount;
	u8 major;
	u8 minor;
	bool palm;
	int palm_count;
	u8 left_event;
};


struct sec_ts_data {
	struct device *dev;
	struct i2c_client *client;
	struct input_dev *input_dev;
	struct input_dev *input_dev_touch;
	struct sec_ts_plat_data *plat_data;
	struct sec_ts_coordinate coord[MAX_SUPPORT_TOUCH_COUNT];

	volatile u8 touch_noise_status;

	int touch_count;
	int tx_count;
	int rx_count;
	int cm_specover;
	int cm_fail_list[6];
	int i2c_burstmax;
	int ta_status;
	volatile int power_status;
	int raw_status;
	int touchkey_glove_mode_status;
	u16 touch_functions;
	struct sec_ts_event_coordinate touchtype;
	struct mutex lock;
	struct mutex device_mutex;
	struct mutex i2c_mutex;
	struct mutex eventlock;

	struct delayed_work work_read_info;
#ifdef CONFIG_SECURE_TOUCH
	atomic_t secure_enabled;
	atomic_t secure_pending_irqs;
	struct completion secure_powerdown;
	struct completion secure_interrupt;
	struct clk *core_clk;
	struct clk *iface_clk;
#endif
	struct wake_lock wakelock;
	short *pFrame;

	bool screen_off;

	int nv;
	int cal_count;

	volatile int wet_mode;

	unsigned char ito_test[4];		/* ito panel tx/rx chanel */
	unsigned char check_multi;
	unsigned int multi_count;		/* multi touch count */
	unsigned int wet_count;			/* wet mode count */
	unsigned int noise_count;		/* noise mode count */
	unsigned int comm_err_count;	/* i2c comm error count */
	unsigned int checksum_result;	/* checksum result */
	unsigned int all_finger_count;
	int max_ambient;
	int max_ambient_channel_tx;
	int max_ambient_channel_rx;
	int min_ambient;
	int min_ambient_channel_tx;
	int min_ambient_channel_rx;

	u32	defect_probability;
#ifdef MINORITY_REPORT
	u8	item_ito;
	u8	item_rawdata;
	u8	item_crc;
	u8	item_i2c_err;
	u8	item_wet;
#endif

	int (*sec_ts_i2c_write)(struct sec_ts_data *ts, u8 reg, u8 *data, int len);
	int (*sec_ts_i2c_read)(struct sec_ts_data *ts, u8 reg, u8 *data, int len);
	int (*sec_ts_i2c_write_burst)(struct sec_ts_data *ts, u8 *data, int len);
	int (*sec_ts_i2c_read_bulk)(struct sec_ts_data *ts, u8 *data, int len);

#ifdef CONFIG_FB
	struct notifier_block fb_notif;
#endif
};

struct sec_ts_plat_data {
	int max_x;
	int max_y;
	unsigned irq_gpio;
	int irq_type;
	int i2c_burstmax;

	const char *firmware_name;
	const char *model_name;
	const char *project_name;
	const char *regulator_dvdd;
	const char *regulator_avdd;

	u8 core_version_of_ic[4];
	u8 config_version_of_ic[4];
	u8 img_version_of_ic[4];

	struct pinctrl *pinctrl;

	int (*power)(void *data, bool on);

	bool regulator_boot_on;
};

int sec_ts_stop_device(struct sec_ts_data *ts);
int sec_ts_start_device(struct sec_ts_data *ts);
int sec_ts_wait_for_ready(struct sec_ts_data *ts, unsigned int ack);
int sec_ts_read_calibration_report(struct sec_ts_data *ts);
int sec_ts_fix_tmode(struct sec_ts_data *ts, u8 mode, u8 state);
int sec_ts_release_tmode(struct sec_ts_data *ts);
int get_tsp_nvm_data(struct sec_ts_data *ts, u8 offset);
void sec_ts_unlocked_release_all_finger(struct sec_ts_data *ts);
void sec_ts_locked_release_all_finger(struct sec_ts_data *ts);
void sec_ts_delay(unsigned int ms);
int sec_ts_read_information(struct sec_ts_data *ts);
#ifdef MINORITY_REPORT
void minority_report_calculate_rawdata(struct sec_ts_data *ts);
void minority_report_calculate_ito(struct sec_ts_data *ts);
void minority_report_sync_latest_value(struct sec_ts_data *ts);
#endif
void sec_ts_run_rawdata_all(struct sec_ts_data *ts, bool full_read);
void sec_ts_reinit(struct sec_ts_data *ts);
void sec_ts_suspend(struct input_dev *dev);
void sec_ts_resume(struct input_dev *dev);

#ifdef CONFIG_SEC_TS_WAKE_GESTURES
int sec_ts_wake_gestures_init(struct sec_ts_data *ts);
int sec_ts_wake_gestures_exit(void);
void sec_ts_detect_doubletap2wake(int x, int y);
extern int dt2w_switch;
extern int dt2w_switch_temp;
extern bool dt2w_switch_changed;
#endif

/*
 * SEC Log
 */
#define SECLOG			"[sec_input]"
#define INPUT_LOG_BUF_SIZE	512

#define input_dbg(mode, dev, fmt, ...)						\
({										\
	static char input_log_buf[INPUT_LOG_BUF_SIZE];				\
	snprintf(input_log_buf, sizeof(input_log_buf), "%s %s", SECLOG, fmt);	\
	dev_dbg(dev, input_log_buf, ## __VA_ARGS__);				\
})
#define input_info(mode, dev, fmt, ...)						\
({										\
	static char input_log_buf[INPUT_LOG_BUF_SIZE];				\
	snprintf(input_log_buf, sizeof(input_log_buf), "%s %s", SECLOG, fmt);	\
	dev_info(dev, input_log_buf, ## __VA_ARGS__);				\
})
#define input_err(mode, dev, fmt, ...)						\
({										\
	static char input_log_buf[INPUT_LOG_BUF_SIZE];				\
	snprintf(input_log_buf, sizeof(input_log_buf), "%s %s", SECLOG, fmt);	\
	dev_err(dev, input_log_buf, ## __VA_ARGS__);				\
})
#define input_raw_info(mode, dev, fmt, ...) input_info(mode, dev, fmt, ## __VA_ARGS__)

#endif /* __SEC_TS_H__ */
