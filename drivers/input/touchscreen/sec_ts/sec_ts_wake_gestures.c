/*
 * drivers/input/touchscreen/sec_ts/sec_ts_wake_gestures.c
 *
 *
 * Copyright (c) 2013, Dennis Rassmann <showp1984@gmail.com>
 * Copyright (c) 2013-18 Aaron Segaert <asegaert@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/err.h>
#include "include/sec_ts_wake_gestures.h" /* <linux/wake_gestures.h> */
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/input.h>
#include <linux/hrtimer.h>
#include <asm-generic/cputime.h>

/* Tuneables */
#define WG_DEBUG		0
#define WG_DEFAULT		0
#define DT2W_DEFAULT		0
#define WG_PWRKEY_DUR           60

/* GM 9 Pro */
#define DT2W_FEATHER		150
#define DT2W_TIME 		300 /* 500 */

/* Wake Gestures */
#define TRIGGER_TIMEOUT		500

#define LOGTAG			"WG"

/* Resources */
int dt2w_switch = DT2W_DEFAULT;
int dt2w_switch_temp;
bool dt2w_switch_changed = false;
static int touch_x = 0, touch_y = 0;
static bool touch_x_called = false, touch_y_called = false;
static bool exec_count = true;
static unsigned long pwrtrigger_time[2] = {0, 0};
static unsigned long long tap_time_pre = 0;
static int touch_nr = 0, x_pre = 0, y_pre = 0;
static bool touch_cnt = true;

static struct input_dev * wake_dev;
static DEFINE_MUTEX(pwrkeyworklock);
static struct workqueue_struct *dt2w_input_wq;
static struct work_struct dt2w_input_work;

static bool is_suspended(void)
{
	return scr_suspended();
}

/* PowerKey work func */
static void wake_presspwr(struct work_struct * wake_presspwr_work) {
	if (!mutex_trylock(&pwrkeyworklock))
		return;

	input_event(wake_dev, EV_KEY, KEY_POWER, 1);
	input_event(wake_dev, EV_SYN, 0, 0);
	msleep(WG_PWRKEY_DUR);
	input_event(wake_dev, EV_KEY, KEY_POWER, 0);
	input_event(wake_dev, EV_SYN, 0, 0);
	msleep(WG_PWRKEY_DUR);
	mutex_unlock(&pwrkeyworklock);

	return;
}
static DECLARE_WORK(wake_presspwr_work, wake_presspwr);

/* PowerKey trigger */
static void wake_pwrtrigger(void) {
	pwrtrigger_time[1] = pwrtrigger_time[0];
	pwrtrigger_time[0] = ktime_to_ms(ktime_get());

	if (pwrtrigger_time[0] - pwrtrigger_time[1] < TRIGGER_TIMEOUT)
		return;

	schedule_work(&wake_presspwr_work);

        return;
}


/* Doubletap2wake */

static void doubletap2wake_reset(void) {
	exec_count = true;
	touch_nr = 0;
	tap_time_pre = 0;
	x_pre = 0;
	y_pre = 0;
}

static unsigned int calc_feather(int coord, int prev_coord) {
	int calc_coord = 0;
	calc_coord = coord-prev_coord;
	if (calc_coord < 0)
		calc_coord = calc_coord * (-1);
	return calc_coord;
}

/* init a new touch */
static void new_touch(int x, int y) {
	tap_time_pre = ktime_to_ms(ktime_get());
	x_pre = x;
	y_pre = y;
	touch_nr++;
}

/* Doubletap2wake main function */
static void detect_doubletap2wake(int x, int y, bool st)
{
        bool single_touch = st;
#if WG_DEBUG
        pr_info(LOGTAG"x,y(%4d,%4d) tap_time_pre:%llu\n",
                x, y, tap_time_pre);
#endif
	if ((single_touch) && (dt2w_switch) && (exec_count) && (touch_cnt)) {
		touch_cnt = false;
		if (touch_nr == 0) {
			new_touch(x, y);
		} else if (touch_nr == 1) {
			if ((calc_feather(x, x_pre) < DT2W_FEATHER) &&
			    (calc_feather(y, y_pre) < DT2W_FEATHER) &&
			    ((ktime_to_ms(ktime_get())-tap_time_pre) < DT2W_TIME))
				touch_nr++;
			else {
				doubletap2wake_reset();
				new_touch(x, y);
			}
		} else {
			doubletap2wake_reset();
			new_touch(x, y);
		}
		if ((touch_nr > 1)) {
			exec_count = false;

			wake_pwrtrigger();
			doubletap2wake_reset();
		}
	}
}

static void dt2w_input_callback(struct work_struct *unused)
{

	if (is_suspended() && dt2w_switch)
		detect_doubletap2wake(touch_x, touch_y, true);
	return;
}

static void wg_input_event(struct input_handle *handle, unsigned int type,
				unsigned int code, int value)
{
	if (is_suspended() && code == ABS_MT_POSITION_X) {
		value -= 5000;
	}

#if WG_DEBUG
	pr_info("wg: code: %s|%u, val: %i\n",
		((code==ABS_MT_POSITION_X) ? "X" :
		(code==ABS_MT_POSITION_Y) ? "Y" :
		(code==ABS_MT_TRACKING_ID) ? "ID" :
		"undef"), code, value);
#endif

	if (code == ABS_MT_SLOT) {
		doubletap2wake_reset();
		return;
	}

	if (code == ABS_MT_TRACKING_ID && value == -1) {
		touch_cnt = true;
		queue_work_on(0, dt2w_input_wq, &dt2w_input_work);
		return;
	}

	if (code == ABS_MT_POSITION_X) {
		touch_x = value;
		touch_x_called = true;
	}

	if (code == ABS_MT_POSITION_Y) {
		touch_y = value;
		touch_y_called = true;
	}

	if (touch_x_called && touch_y_called) {
		touch_x_called = false;
		touch_y_called = false;
	} else if (!is_suspended() && touch_x_called && !touch_y_called) {
		touch_x_called = false;
		touch_y_called = false;
	}
}

static int input_dev_filter(struct input_dev *dev) {
	if (strstr(dev->name, "sec_touchscreen")) {
		return 0;
	} else {
		return 1;
	}
}

static int wg_input_connect(struct input_handler *handler,
				struct input_dev *dev, const struct input_device_id *id) {
	struct input_handle *handle;
	int error;

	if (input_dev_filter(dev))
		return -ENODEV;

	handle = kzalloc(sizeof(struct input_handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	handle->dev = dev;
	handle->handler = handler;
	handle->name = "wg";

	error = input_register_handle(handle);
	if (error)
		goto err2;

	error = input_open_device(handle);
	if (error)
		goto err1;

	return 0;
err1:
	input_unregister_handle(handle);
err2:
	kfree(handle);
	return error;
}

static void wg_input_disconnect(struct input_handle *handle) {
	input_close_device(handle);
	input_unregister_handle(handle);
	kfree(handle);
}

static const struct input_device_id wg_ids[] = {
	{ .driver_info = 1 },
	{ },
};

static struct input_handler wg_input_handler = {
	.event		= wg_input_event,
	.connect	= wg_input_connect,
	.disconnect	= wg_input_disconnect,
	.name		= "wg_inputreq",
	.id_table	= wg_ids,
};


/*
 * SYSFS stuff below here
 */
static ssize_t doubletap2wake_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	size_t count = 0;

	count += sprintf(buf, "%d\n", dt2w_switch);

	return count;
}

static ssize_t doubletap2wake_dump(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	sscanf(buf, "%d ", &dt2w_switch_temp);
	if (dt2w_switch_temp < 0 || dt2w_switch_temp > 1)
		dt2w_switch_temp = 0;

	if (!scr_suspended())
		dt2w_switch = dt2w_switch_temp;
	else
		dt2w_switch_changed = true;

	return count;
}

static DEVICE_ATTR(doubletap2wake, (S_IWUSR|S_IRUGO),
	doubletap2wake_show, doubletap2wake_dump);

/*
 * INIT / EXIT stuff below here
 */

struct kobject *android_touch_kobj;
EXPORT_SYMBOL_GPL(android_touch_kobj);

static int __init wake_gestures_init(void)
{
	int rc = 0;

	wake_dev = input_allocate_device();
	if (!wake_dev) {
		pr_err("Failed to allocate wake_dev\n");
		goto err_alloc_dev;
	}

	input_set_capability(wake_dev, EV_KEY, KEY_POWER);
	wake_dev->name = "wg_pwrkey";
	wake_dev->phys = "wg_pwrkey/input0";

	rc = input_register_device(wake_dev);
	if (rc) {
		pr_err("%s: input_register_device err=%d\n", __func__, rc);
		goto err_input_dev;
	}

	rc = input_register_handler(&wg_input_handler);
	if (rc)
		pr_err("%s: Failed to register wg_input_handler\n", __func__);

	dt2w_input_wq = create_workqueue("dt2wiwq");
	if (!dt2w_input_wq) {
		pr_err("%s: Failed to create dt2wiwq workqueue\n", __func__);
		return -EFAULT;
	}
	INIT_WORK(&dt2w_input_work, dt2w_input_callback);

	android_touch_kobj = kobject_create_and_add("android_touch", NULL) ;
	if (android_touch_kobj == NULL) {
		pr_warn("%s: android_touch_kobj create_and_add failed\n", __func__);
	}

	rc = sysfs_create_file(android_touch_kobj, &dev_attr_doubletap2wake.attr);
	if (rc) {
		pr_warn("%s: sysfs_create_file failed for doubletap2wake\n", __func__);
	}

err_input_dev:
	input_free_device(wake_dev);
err_alloc_dev:

	return 0;
}

static void __exit wake_gestures_exit(void)
{
	kobject_del(android_touch_kobj);
	input_unregister_handler(&wg_input_handler);
	destroy_workqueue(dt2w_input_wq);
	input_unregister_device(wake_dev);
	input_free_device(wake_dev);

	return;
}

module_init(wake_gestures_init);
module_exit(wake_gestures_exit);

