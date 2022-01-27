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

#include "include/sec_ts.h"

/* Resources */
int dt2w_switch;
int dt2w_switch_temp;
bool dt2w_switch_changed;
static bool exec_count = true;
static unsigned long pwrtrigger_time[2] = {0, 0};
static unsigned long long tap_time_pre = 0;
static int touch_nr = 0, x_pre = 0, y_pre = 0;
static bool touch_cnt = true;

static struct input_dev * sec_ts_dev;
static DEFINE_MUTEX(pwrkeyworklock);

/* PowerKey work func */
static void wake_presspwr(struct work_struct * wake_presspwr_work) {
	if (!mutex_trylock(&pwrkeyworklock))
		return;

	input_event(sec_ts_dev, EV_KEY, KEY_POWER, 1);
	input_event(sec_ts_dev, EV_SYN, 0, 0);
	msleep(WG_PWRKEY_DUR);
	input_event(sec_ts_dev, EV_KEY, KEY_POWER, 0);
	input_event(sec_ts_dev, EV_SYN, 0, 0);
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
void sec_ts_detect_doubletap2wake(int x, int y)
{
	if (exec_count) {
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
	struct sec_ts_data *ts = input_get_drvdata(sec_ts_dev);

	sscanf(buf, "%d ", &dt2w_switch_temp);
	if (dt2w_switch_temp < 0 || dt2w_switch_temp > 1)
		dt2w_switch_temp = 0;

	if (ts->screen_off)
		dt2w_switch_changed = true;
	else
		dt2w_switch = dt2w_switch_temp;

	return count;
}

static DEVICE_ATTR(doubletap2wake, (S_IWUSR|S_IRUGO),
	doubletap2wake_show, doubletap2wake_dump);

/*
 * INIT / EXIT stuff below here
 */
struct kobject *android_touch_kobj;
EXPORT_SYMBOL_GPL(android_touch_kobj);

int sec_ts_wake_gestures_init(struct sec_ts_data *ts)
{
	int rc = 0;
	dt2w_switch = 0;
	dt2w_switch_temp = 0;
	dt2w_switch_changed = false;
	sec_ts_dev = ts->input_dev;

	input_set_capability(sec_ts_dev, EV_KEY, KEY_POWER);

	android_touch_kobj = kobject_create_and_add("android_touch", NULL) ;
	if (android_touch_kobj == NULL) {
		pr_warn("%s: android_touch_kobj create_and_add failed\n", __func__);
	}

	rc = sysfs_create_file(android_touch_kobj, &dev_attr_doubletap2wake.attr);
	if (rc) {
		pr_warn("%s: sysfs_create_file failed for doubletap2wake\n", __func__);
	}

	return 0;
}

int sec_ts_wake_gestures_exit(void)
{
	kobject_del(android_touch_kobj);
	return 0;
}
