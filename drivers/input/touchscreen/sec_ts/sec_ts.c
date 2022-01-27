/* drivers/input/touchscreen/sec_ts.c
 *
 * Copyright (C) 2011 Samsung Electronics Co., Ltd.
 * http://www.samsungsemi.com/
 *
 * Core file for Samsung TSC driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "include/sec_ts.h"

static void sec_ts_read_info_work(struct work_struct *work);

#ifdef USE_OPEN_CLOSE
static int sec_ts_input_open(struct input_dev *dev);
static void sec_ts_input_close(struct input_dev *dev);
#endif

int sec_ts_read_information(struct sec_ts_data *ts);

#ifdef CONFIG_SECURE_TOUCH
static int sec_ts_change_pipe_owner(struct sec_ts_data *ts, enum subsystem subsystem)
{
	/* scm call disciptor */
	struct scm_desc desc;
	int ret = 0;

	/* number of arguments */
	desc.arginfo = SCM_ARGS(2);
	/* BLSPID (1 - 12) */
	desc.args[0] = (u64)(ts->client->adapter->nr) - 1;
	/* Owner if TZ or APSS */
	desc.args[1] = subsystem;

	ret = scm_call2(SCM_SIP_FNID(SCM_SVC_TZ, TZ_BLSP_MODIFY_OWNERSHIP_ID), &desc);
	if (ret) {
		input_err(true, &ts->client->dev, "%s: ret: %d\n", __func__, ret);
		return ret;
	}

	input_dbg(true, &ts->client->dev, "%s: return: %llu\n", __func__, desc.ret[0]);

	return desc.ret[0];
}

static irqreturn_t sec_ts_irq_thread(int irq, void *ptr);

static irqreturn_t secure_filter_interrupt(struct sec_ts_data *ts)
{
	if (atomic_read(&ts->secure_enabled) == SECURE_TOUCH_ENABLE) {
		if (atomic_cmpxchg(&ts->secure_pending_irqs, 0, 1) == 0) {
			sysfs_notify(&ts->input_dev->dev.kobj, NULL, "secure_touch");
		} else {
			input_info(true, &ts->client->dev, "%s: pending irq:%d\n",
					__func__, (int)atomic_read(&ts->secure_pending_irqs));
		}

		return IRQ_HANDLED;
	}

	return IRQ_NONE;
}

static int secure_touch_clk_prepare_enable(struct sec_ts_data *ts)
{
	int ret;

	if (!ts->core_clk || !ts->iface_clk) {
		input_err(true, &ts->client->dev, "%s: error clk\n", __func__);
		return -ENODEV;
	}

	ret = clk_prepare_enable(ts->core_clk);
	if (ret < 0) {
		input_err(true, &ts->client->dev, "%s: failed core clk\n", __func__);
		goto err_core_clk;
	}

	ret = clk_prepare_enable(ts->iface_clk);
	if (ret < 0) {
		input_err(true, &ts->client->dev, "%s: failed iface clk\n", __func__);
		goto err_iface_clk;
	}

	return 0;

err_iface_clk:
	clk_disable_unprepare(ts->core_clk);
err_core_clk:
	return -ENODEV;
}

static void secure_touch_clk_unprepare_disable(struct sec_ts_data *ts)
{
	if (!ts->core_clk || !ts->iface_clk) {
		input_err(true, &ts->client->dev, "%s: error clk\n", __func__);
		return;
	}

	clk_disable_unprepare(ts->core_clk);
	clk_disable_unprepare(ts->iface_clk);
}

/**
 * Sysfs attr group for secure touch & interrupt handler for Secure world.
 * @atomic : syncronization for secure_enabled
 * @pm_runtime : set rpm_resume or rpm_ilde
 */
static ssize_t secure_touch_enable_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct sec_ts_data *ts = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%d", atomic_read(&ts->secure_enabled));
}

static ssize_t secure_touch_enable_store(struct device *dev,
		struct device_attribute *addr, const char *buf, size_t count)
{
	struct sec_ts_data *ts = dev_get_drvdata(dev);
	int ret;
	unsigned long data;

	if (count > 2) {
		input_err(true, &ts->client->dev,
				"%s: cmd length is over (%s,%d)!!\n",
				__func__, buf, (int)strlen(buf));
		return -EINVAL;
	}

	ret = kstrtoul(buf, 10, &data);
	if (ret != 0) {
		input_err(true, &ts->client->dev, "%s: failed to read:%d\n",
				__func__, ret);
		return -EINVAL;
	}

	if (data == 1) {
		/* Enable Secure World */
		if (atomic_read(&ts->secure_enabled) == SECURE_TOUCH_ENABLE) {
			input_err(true, &ts->client->dev, "%s: already enabled\n", __func__);
			return -EBUSY;
		}

		/* syncronize_irq -> disable_irq + enable_irq
		 * concern about timing issue.
		 */
		disable_irq(ts->client->irq);

		/* Fix normal active mode : idle mode is failed to i2c for 1 time */
		ret = sec_ts_fix_tmode(ts, TOUCH_SYSTEM_MODE_TOUCH, TOUCH_MODE_STATE_TOUCH);
		if (ret < 0) {
			enable_irq(ts->client->irq);
			input_err(true, &ts->client->dev, "%s: failed to fix tmode\n",
					__func__);
			return -EIO;
		}

		/* Release All Finger */
		sec_ts_unlocked_release_all_finger(ts);

		if (pm_runtime_get_sync(ts->client->adapter->dev.parent) < 0) {
			enable_irq(ts->client->irq);
			input_err(true, &ts->client->dev, "%s: failed to get pm_runtime\n", __func__);
			return -EIO;
		}

		if (secure_touch_clk_prepare_enable(ts) < 0) {
			pm_runtime_put_sync(ts->client->adapter->dev.parent);
			enable_irq(ts->client->irq);
			input_err(true, &ts->client->dev, "%s: failed to clk enable\n", __func__);
			return -ENXIO;
		}

		sec_ts_change_pipe_owner(ts, TZ);

		reinit_completion(&ts->secure_powerdown);
		reinit_completion(&ts->secure_interrupt);

		atomic_set(&ts->secure_enabled, 1);
		atomic_set(&ts->secure_pending_irqs, 0);

		enable_irq(ts->client->irq);

		input_info(true, &ts->client->dev, "%s: secure touch enable\n", __func__);
	} else if (data == 0) {
		/* Disable Secure World */
		if (atomic_read(&ts->secure_enabled) == SECURE_TOUCH_DISABLE) {
			input_err(true, &ts->client->dev, "%s: already disabled\n", __func__);
			return count;
		}

		sec_ts_change_pipe_owner(ts, APSS);

		secure_touch_clk_unprepare_disable(ts);
		pm_runtime_put_sync(ts->client->adapter->dev.parent);
		atomic_set(&ts->secure_enabled, 0);

		sysfs_notify(&ts->input_dev->dev.kobj, NULL, "secure_touch");

		sec_ts_delay(10);

		sec_ts_irq_thread(ts->client->irq, ts);
		complete(&ts->secure_interrupt);
		complete(&ts->secure_powerdown);

		input_info(true, &ts->client->dev, "%s: secure touch disable\n", __func__);

		ret = sec_ts_release_tmode(ts);
		if (ret < 0) {
			input_err(true, &ts->client->dev, "%s: failed to release tmode\n",
					__func__);
			return -EIO;
		}

	} else {
		input_err(true, &ts->client->dev, "%s: unsupport value:%d\n", __func__, data);
		return -EINVAL;
	}

	return count;
}

static ssize_t secure_touch_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct sec_ts_data *ts = dev_get_drvdata(dev);
	int val = 0;

	if (atomic_read(&ts->secure_enabled) == SECURE_TOUCH_DISABLE) {
		input_err(true, &ts->client->dev, "%s: disabled\n", __func__);
		return -EBADF;
	}

	if (atomic_cmpxchg(&ts->secure_pending_irqs, -1, 0) == -1) {
		input_err(true, &ts->client->dev, "%s: pending irq -1\n", __func__);
		return -EINVAL;
	}

	if (atomic_cmpxchg(&ts->secure_pending_irqs, 1, 0) == 1)
		val = 1;

	input_err(true, &ts->client->dev, "%s: pending irq is %d\n",
			__func__, atomic_read(&ts->secure_pending_irqs));

	complete(&ts->secure_interrupt);

	return snprintf(buf, PAGE_SIZE, "%u", val);
}

static ssize_t secure_ownership_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "1");
}

static DEVICE_ATTR(secure_touch_enable, (S_IRUGO | S_IWUSR | S_IWGRP),
		secure_touch_enable_show, secure_touch_enable_store);
static DEVICE_ATTR(secure_touch, S_IRUGO, secure_touch_show, NULL);

static DEVICE_ATTR(secure_ownership, S_IRUGO, secure_ownership_show, NULL);

static struct attribute *secure_attr[] = {
	&dev_attr_secure_touch_enable.attr,
	&dev_attr_secure_touch.attr,
	&dev_attr_secure_ownership.attr,
	NULL,
};

static struct attribute_group secure_attr_group = {
	.attrs = secure_attr,
};

static int secure_touch_init(struct sec_ts_data *ts)
{
	input_info(true, &ts->client->dev, "%s\n", __func__);

	init_completion(&ts->secure_interrupt);
	init_completion(&ts->secure_powerdown);

	ts->core_clk = clk_get(&ts->client->adapter->dev, "core_clk");
	if (IS_ERR_OR_NULL(ts->core_clk)) {
		input_err(true, &ts->client->dev, "%s: failed to get core_clk: %ld\n",
				__func__, PTR_ERR(ts->core_clk));
		goto err_core_clk;
	}

	ts->iface_clk = clk_get(&ts->client->adapter->dev, "iface_clk");
	if (IS_ERR_OR_NULL(ts->iface_clk)) {
		input_err(true, &ts->client->dev, "%s: failed to get iface_clk: %ld\n",
				__func__, PTR_ERR(ts->iface_clk));
		goto err_iface_clk;
	}

	return 0;

err_iface_clk:
	clk_put(ts->core_clk);
err_core_clk:
	ts->core_clk = NULL;
	ts->iface_clk = NULL;

	return -ENODEV;
}

static void secure_touch_remove(struct sec_ts_data *ts)
{
	if (!IS_ERR_OR_NULL(ts->core_clk))
		clk_put(ts->core_clk);

	if (!IS_ERR_OR_NULL(ts->iface_clk))
		clk_put(ts->iface_clk);
}

static void secure_touch_stop(struct sec_ts_data *ts, bool stop)
{
	if (atomic_read(&ts->secure_enabled)) {
		atomic_set(&ts->secure_pending_irqs, -1);

		sysfs_notify(&ts->input_dev->dev.kobj, NULL, "secure_touch");

		if (stop)
			wait_for_completion_interruptible(&ts->secure_powerdown);

		input_info(true, &ts->client->dev, "%s: %d\n", __func__, stop);
	}
}
#endif

int sec_ts_i2c_write(struct sec_ts_data *ts, u8 reg, u8 *data, int len)
{
	u8 buf[I2C_WRITE_BUFFER_SIZE + 1];
	int ret;
	unsigned char retry;
	struct i2c_msg msg;

#ifdef CONFIG_SECURE_TOUCH
	if (atomic_read(&ts->secure_enabled) == SECURE_TOUCH_ENABLE) {
		input_err(true, &ts->client->dev,
				"%s: TSP no accessible from Linux, TUI is enabled!\n", __func__);
		return -EBUSY;
	}
#endif

	if (len > I2C_WRITE_BUFFER_SIZE) {
		input_err(true, &ts->client->dev, "%s: len is larger than buffer size\n", __func__);
		return -EINVAL;
	}

	if (ts->power_status == SEC_TS_STATE_POWER_OFF) {
		input_err(true, &ts->client->dev, "%s: POWER_STATUS : OFF\n", __func__);
		goto err;
	}

	buf[0] = reg;
	memcpy(buf + 1, data, len);

	msg.addr = ts->client->addr;
	msg.flags = 0;
	msg.len = len + 1;
	msg.buf = buf;
	mutex_lock(&ts->i2c_mutex);
	for (retry = 0; retry < SEC_TS_I2C_RETRY_CNT; retry++) {
		if ((ret = i2c_transfer(ts->client->adapter, &msg, 1)) == 1)
			break;

		if (ts->power_status == SEC_TS_STATE_POWER_OFF) {
			input_err(true, &ts->client->dev, "%s: POWER_STATUS : OFF, retry:%d\n", __func__, retry);
			mutex_unlock(&ts->i2c_mutex);
			goto err;
		}

		usleep_range(1 * 1000, 1 * 1000);

		if (retry > 1) {
			input_err(true, &ts->client->dev, "%s: I2C retry %d\n", __func__, retry + 1);
			ts->comm_err_count++;
		}
	}

	mutex_unlock(&ts->i2c_mutex);

	if (retry == SEC_TS_I2C_RETRY_CNT) {
		input_err(true, &ts->client->dev, "%s: I2C write over retry limit\n", __func__);
		ret = -EIO;
	}

	if (ret == 1)
		return 0;
err:
	return -EIO;
}

int sec_ts_i2c_read(struct sec_ts_data *ts, u8 reg, u8 *data, int len)
{
	u8 buf[4];
	int ret;
	unsigned char retry;
	struct i2c_msg msg[2];
	int remain = len;

#ifdef CONFIG_SECURE_TOUCH
	if (atomic_read(&ts->secure_enabled) == SECURE_TOUCH_ENABLE) {
		input_err(true, &ts->client->dev,
				"%s: TSP no accessible from Linux, TUI is enabled!\n", __func__);
		return -EBUSY;
	}
#endif

	if (ts->power_status == SEC_TS_STATE_POWER_OFF) {
		input_err(true, &ts->client->dev, "%s: POWER_STATUS : OFF\n", __func__);
		goto err;
	}

	buf[0] = reg;

	msg[0].addr = ts->client->addr;
	msg[0].flags = 0;
	msg[0].len = 1;
	msg[0].buf = buf;

	msg[1].addr = ts->client->addr;
	msg[1].flags = I2C_M_RD;
	msg[1].len = len;
	msg[1].buf = data;

	mutex_lock(&ts->i2c_mutex);

	if (len <= ts->i2c_burstmax) {

		for (retry = 0; retry < SEC_TS_I2C_RETRY_CNT; retry++) {
			ret = i2c_transfer(ts->client->adapter, msg, 2);
			if (ret == 2)
				break;
			usleep_range(1 * 1000, 1 * 1000);
			if (ts->power_status == SEC_TS_STATE_POWER_OFF) {
				input_err(true, &ts->client->dev, "%s: POWER_STATUS : OFF, retry:%d\n", __func__, retry);
				mutex_unlock(&ts->i2c_mutex);
				goto err;
			}

			if (retry > 1) {
				input_err(true, &ts->client->dev, "%s: I2C retry %d\n", __func__, retry + 1);
				ts->comm_err_count++;
			}
		}

	} else {
		/*
		 * I2C read buffer is 256 byte. do not support long buffer over than 256.
		 * So, try to seperate reading data about 256 bytes.
		 */

		for (retry = 0; retry < SEC_TS_I2C_RETRY_CNT; retry++) {
			ret = i2c_transfer(ts->client->adapter, msg, 1);
			if (ret == 1)
				break;
			usleep_range(1 * 1000, 1 * 1000);
			if (ts->power_status == SEC_TS_STATE_POWER_OFF) {
				input_err(true, &ts->client->dev, "%s: POWER_STATUS : OFF, retry:%d\n", __func__, retry);
				mutex_unlock(&ts->i2c_mutex);
				goto err;
			}

			if (retry > 1) {
				input_err(true, &ts->client->dev, "%s: I2C retry %d\n", __func__, retry + 1);
				ts->comm_err_count++;
			}
		}

		do {
			if (remain > ts->i2c_burstmax)
				msg[1].len = ts->i2c_burstmax;
			else
				msg[1].len = remain;

			remain -= ts->i2c_burstmax;

			for (retry = 0; retry < SEC_TS_I2C_RETRY_CNT; retry++) {
				ret = i2c_transfer(ts->client->adapter, &msg[1], 1);
				if (ret == 1)
					break;
				usleep_range(1 * 1000, 1 * 1000);
				if (ts->power_status == SEC_TS_STATE_POWER_OFF) {
					input_err(true, &ts->client->dev, "%s: POWER_STATUS : OFF, retry:%d\n", __func__, retry);
					mutex_unlock(&ts->i2c_mutex);
					goto err;
				}

				if (retry > 1) {
					input_err(true, &ts->client->dev, "%s: I2C retry %d\n", __func__, retry + 1);
					ts->comm_err_count++;
				}
			}

			msg[1].buf += msg[1].len;

		} while (remain > 0);

	}

	mutex_unlock(&ts->i2c_mutex);

	if (retry == SEC_TS_I2C_RETRY_CNT) {
		input_err(true, &ts->client->dev, "%s: I2C read over retry limit\n", __func__);
		ret = -EIO;
	}

	return ret;

err:
	return -EIO;
}

static int sec_ts_i2c_write_burst(struct sec_ts_data *ts, u8 *data, int len)
{
	int ret;
	int retry;

#ifdef CONFIG_SECURE_TOUCH
	if (atomic_read(&ts->secure_enabled) == SECURE_TOUCH_ENABLE) {
		input_err(true, &ts->client->dev,
				"%s: TSP no accessible from Linux, TUI is enabled\n", __func__);
		return -EBUSY;
	}
#endif

	mutex_lock(&ts->i2c_mutex);
	for (retry = 0; retry < SEC_TS_I2C_RETRY_CNT; retry++) {
		if ((ret = i2c_master_send(ts->client, data, len)) == len)
			break;

		usleep_range(1 * 1000, 1 * 1000);

		if (retry > 1) {
			input_err(true, &ts->client->dev, "%s: I2C retry %d\n", __func__, retry + 1);
			ts->comm_err_count++;
		}
	}

	mutex_unlock(&ts->i2c_mutex);
	if (retry == SEC_TS_I2C_RETRY_CNT) {
		input_err(true, &ts->client->dev, "%s: I2C write over retry limit\n", __func__);
		ret = -EIO;
	}

	return ret;
}

static int sec_ts_i2c_read_bulk(struct sec_ts_data *ts, u8 *data, int len)
{
	int ret;
	unsigned char retry;
	int remain = len;
	struct i2c_msg msg;

#ifdef CONFIG_SECURE_TOUCH
	if (atomic_read(&ts->secure_enabled) == SECURE_TOUCH_ENABLE) {
		input_err(true, &ts->client->dev,
				"%s: TSP no accessible from Linux, TUI is enabled\n", __func__);
		return -EBUSY;
	}
#endif

	msg.addr = ts->client->addr;
	msg.flags = I2C_M_RD;
	msg.len = len;
	msg.buf = data;

	mutex_lock(&ts->i2c_mutex);

	do {
		if (remain > ts->i2c_burstmax)
			msg.len = ts->i2c_burstmax;
		else
			msg.len = remain;

		remain -= ts->i2c_burstmax;

		for (retry = 0; retry < SEC_TS_I2C_RETRY_CNT; retry++) {
			ret = i2c_transfer(ts->client->adapter, &msg, 1);
			if (ret == 1)
				break;
			usleep_range(1 * 1000, 1 * 1000);

			if (retry > 1) {
				input_err(true, &ts->client->dev, "%s: I2C retry %d\n", __func__, retry + 1);
				ts->comm_err_count++;
			}
		}

		if (retry == SEC_TS_I2C_RETRY_CNT) {
			input_err(true, &ts->client->dev, "%s: I2C read over retry limit\n", __func__);
			ret = -EIO;

			break;
		}
		msg.buf += msg.len;

	} while (remain > 0);

	mutex_unlock(&ts->i2c_mutex);

	if (ret == 1)
		return 0;

	return -EIO;
}

void sec_ts_delay(unsigned int ms)
{
	if (ms < 20)
		usleep_range(ms * 1000, ms * 1000);
	else
		msleep(ms);
}

int sec_ts_wait_for_ready(struct sec_ts_data *ts, unsigned int ack)
{
	int rc = -1;
	int retry = 0;
	u8 tBuff[SEC_TS_EVENT_BUFF_SIZE] = {0,};

	while (sec_ts_i2c_read(ts, SEC_TS_READ_ONE_EVENT, tBuff, SEC_TS_EVENT_BUFF_SIZE) > 0) {
		if (((tBuff[0] >> 2) & 0xF) == TYPE_STATUS_EVENT_INFO) {
			if (tBuff[1] == ack) {
				rc = 0;
				break;
			}
		} else if (((tBuff[0] >> 2) & 0xF) == TYPE_STATUS_EVENT_VENDOR_INFO) {
			if (tBuff[1] == ack) {
				rc = 0;
				break;
			}
		}

		if (retry++ > SEC_TS_WAIT_RETRY_CNT) {
			input_err(true, &ts->client->dev, "%s: Time Over\n", __func__);
			break;
		}
		sec_ts_delay(20);
	}

	return rc;
}

int sec_ts_read_calibration_report(struct sec_ts_data *ts)
{
	int ret;
	u8 buf[5] = { 0 };

	buf[0] = SEC_TS_READ_CALIBRATION_REPORT;

	ret = sec_ts_i2c_read(ts, buf[0], &buf[1], 4);
	if (ret < 0) {
		input_err(true, &ts->client->dev, "%s: failed to read, %d\n", __func__, ret);
		return ret;
	}

	input_info(true, &ts->client->dev, "%s: count:%d, pass count:%d, fail count:%d, status:0x%X\n",
			__func__, buf[1], buf[2], buf[3], buf[4]);

	return buf[4];
}

void sec_ts_reinit(struct sec_ts_data *ts)
{
	ts->touch_noise_status = 0;
	return;
}

#define MAX_EVENT_COUNT 32
static void sec_ts_read_event(struct sec_ts_data *ts)
{
	int ret;
	u8 t_id;
	u8 event_id;
	u8 left_event_count;
	u8 read_event_buff[MAX_EVENT_COUNT][SEC_TS_EVENT_BUFF_SIZE] = { { 0 } };
	u8 *event_buff;
	struct sec_ts_event_coordinate *p_event_coord;
	struct sec_ts_event_status *p_event_status;
	int curr_pos;
	int remain_event_count = 0;
	int pre_ttype = 0;

	ret = t_id = event_id = curr_pos = remain_event_count = 0;
	/* repeat READ_ONE_EVENT until buffer is empty(No event) */
	ret = sec_ts_i2c_read(ts, SEC_TS_READ_ONE_EVENT, (u8 *)read_event_buff[0], SEC_TS_EVENT_BUFF_SIZE);
	if (ret < 0) {
		input_err(true, &ts->client->dev, "%s: i2c read one event failed\n", __func__);
		return;
	}

	if (read_event_buff[0][0] == 0) {
		input_info(true, &ts->client->dev, "%s: event buffer is empty\n", __func__);
		return;
	}

	left_event_count = read_event_buff[0][7] & 0x3F;
	remain_event_count = left_event_count;

	if (left_event_count > MAX_EVENT_COUNT - 1 || left_event_count == 0xFF) {
		input_err(true, &ts->client->dev, "%s: event buffer overflow\n", __func__);

		/* write clear event stack command when read_event_count > MAX_EVENT_COUNT */
		ret = sec_ts_i2c_write(ts, SEC_TS_CMD_CLEAR_EVENT_STACK, NULL, 0);
		if (ret < 0)
			input_err(true, &ts->client->dev, "%s: i2c write clear event failed\n", __func__);
		return;
	}

	if (left_event_count > 0) {
		ret = sec_ts_i2c_read(ts, SEC_TS_READ_ALL_EVENT, (u8 *)read_event_buff[1],
				sizeof(u8) * (SEC_TS_EVENT_BUFF_SIZE) * (left_event_count));
		if (ret < 0) {
			input_err(true, &ts->client->dev, "%s: i2c read one event failed\n", __func__);
			return;
		}
	}

	do {
		event_buff = read_event_buff[curr_pos];
		event_id = event_buff[0] & 0x3;

		switch (event_id) {
		case SEC_TS_STATUS_EVENT:
			p_event_status = (struct sec_ts_event_status *)event_buff;

			/* watchdog reset -> send SENSEON command */ /*=>?????*/
			if ((p_event_status->stype == TYPE_STATUS_EVENT_INFO) &&
					(p_event_status->status_id == SEC_TS_ACK_BOOT_COMPLETE) &&
					(p_event_status->status_data_1 == 0x20)) {

				sec_ts_unlocked_release_all_finger(ts);

				ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SENSE_ON, NULL, 0);
				if (ret < 0)
					input_err(true, &ts->client->dev, "%s: fail to write Sense_on\n", __func__);
				sec_ts_reinit(ts);
			}

			/* event queue full-> all finger release */
			if ((p_event_status->stype == TYPE_STATUS_EVENT_ERR) &&
					(p_event_status->status_id == SEC_TS_ERR_EVENT_QUEUE_FULL)) {
				input_err(true, &ts->client->dev, "%s: IC Event Queue is full\n", __func__);
				sec_ts_unlocked_release_all_finger(ts);
			}

			if ((p_event_status->stype == TYPE_STATUS_EVENT_INFO) &&
					(p_event_status->status_id == SEC_TS_ACK_WET_MODE)) {
				ts->wet_mode = p_event_status->status_data_1;
				input_info(true, &ts->client->dev, "%s: water wet mode %d\n",
						__func__, ts->wet_mode);
				if (ts->wet_mode)
					ts->wet_count++;

			}

			if ((p_event_status->stype == TYPE_STATUS_EVENT_VENDOR_INFO) &&
					(p_event_status->status_id == SEC_TS_VENDOR_ACK_NOISE_STATUS_NOTI)) {

				ts->touch_noise_status = !!p_event_status->status_data_1;
				input_info(true, &ts->client->dev, "%s: TSP NOISE MODE %s[%d]\n",
						__func__, ts->touch_noise_status == 0 ? "OFF" : "ON",
						p_event_status->status_data_1);

				if (ts->touch_noise_status)
					ts->noise_count++;
			}

			break;

		case SEC_TS_COORDINATE_EVENT:
			if (ts->power_status != SEC_TS_STATE_POWER_ON) {
				input_err(true, &ts->client->dev, "%s: device is closed\n", __func__);
				break;
			}
			p_event_coord = (struct sec_ts_event_coordinate *)event_buff;

			t_id = (p_event_coord->tid - 1);

			if (t_id < MAX_SUPPORT_TOUCH_COUNT) {
				pre_ttype = ts->coord[t_id].ttype;
				ts->coord[t_id].id = t_id;
				ts->coord[t_id].action = p_event_coord->tchsta;
				ts->coord[t_id].x = (p_event_coord->x_11_4 << 4) | (p_event_coord->x_3_0);
				ts->coord[t_id].y = (p_event_coord->y_11_4 << 4) | (p_event_coord->y_3_0);
				ts->coord[t_id].ttype = p_event_coord->ttype_3_2 << 2 | p_event_coord->ttype_1_0 << 0;
				ts->coord[t_id].major = p_event_coord->major;
				ts->coord[t_id].minor = p_event_coord->minor;

				if (!ts->coord[t_id].palm && (ts->coord[t_id].ttype == SEC_TS_TOUCHTYPE_PALM))
					ts->coord[t_id].palm_count++;

				ts->coord[t_id].palm = (ts->coord[t_id].ttype == SEC_TS_TOUCHTYPE_PALM);
				ts->coord[t_id].left_event = p_event_coord->left_event;

				if ((ts->coord[t_id].ttype == SEC_TS_TOUCHTYPE_NORMAL)
						|| (ts->coord[t_id].ttype == SEC_TS_TOUCHTYPE_PALM)
						|| (ts->coord[t_id].ttype == SEC_TS_TOUCHTYPE_WET)
						|| (ts->coord[t_id].ttype == SEC_TS_TOUCHTYPE_GLOVE)) {

					switch (ts->coord[t_id].action) {
					case SEC_TS_COORDINATE_ACTION_RELEASE:
#ifdef CONFIG_SEC_TS_WAKE_GESTURES
						if (ts->screen_off)
							goto out;
#endif
						input_mt_slot(ts->input_dev, t_id);
						input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, 0);

						if (ts->touch_count > 0)
							ts->touch_count--;
						if (ts->touch_count == 0) {
							input_report_key(ts->input_dev, BTN_TOUCH, 0);
							input_report_key(ts->input_dev, BTN_TOOL_FINGER, 0);
							ts->check_multi = 0;
						}

						ts->coord[t_id].action = SEC_TS_COORDINATE_ACTION_NONE;
						ts->coord[t_id].mcount = 0;
						ts->coord[t_id].palm_count = 0;

						break;
					case SEC_TS_COORDINATE_ACTION_PRESS:
#ifdef CONFIG_SEC_TS_WAKE_GESTURES
						if (ts->screen_off) {
							if (dt2w_switch)
								sec_ts_detect_doubletap2wake(ts->coord[t_id].x, ts->coord[t_id].y);
							goto out;
						}
#endif
						ts->touch_count++;
						ts->all_finger_count++;
						input_mt_slot(ts->input_dev, t_id);
						input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, 1);
						input_report_key(ts->input_dev, BTN_TOUCH, 1);
						input_report_key(ts->input_dev, BTN_TOOL_FINGER, 1);

						input_report_abs(ts->input_dev, ABS_MT_POSITION_X, ts->coord[t_id].x);
						input_report_abs(ts->input_dev, ABS_MT_POSITION_Y, ts->coord[t_id].y);
						input_report_abs(ts->input_dev, ABS_MT_TOUCH_MAJOR, ts->coord[t_id].major);
						input_report_abs(ts->input_dev, ABS_MT_TOUCH_MINOR, ts->coord[t_id].minor);

						if ((ts->touch_count > 4) && (ts->check_multi == 0)) {
							ts->check_multi = 1;
							ts->multi_count++;
						}
						break;
					case SEC_TS_COORDINATE_ACTION_MOVE:
#ifdef CONFIG_SEC_TS_WAKE_GESTURES
						if (ts->screen_off)
							goto out;
#endif
						if ((ts->coord[t_id].ttype == SEC_TS_TOUCHTYPE_GLOVE) && !ts->touchkey_glove_mode_status) {
							ts->touchkey_glove_mode_status = true;
							input_report_switch(ts->input_dev, SW_GLOVE, 1);
						} else {
							ts->touchkey_glove_mode_status = false;
							input_report_switch(ts->input_dev, SW_GLOVE, 0);
						}

						input_mt_slot(ts->input_dev, t_id);
						input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, 1);
						input_report_key(ts->input_dev, BTN_TOUCH, 1);
						input_report_key(ts->input_dev, BTN_TOOL_FINGER, 1);

						input_report_abs(ts->input_dev, ABS_MT_POSITION_X, ts->coord[t_id].x);
						input_report_abs(ts->input_dev, ABS_MT_POSITION_Y, ts->coord[t_id].y);
						input_report_abs(ts->input_dev, ABS_MT_TOUCH_MAJOR, ts->coord[t_id].major);
						input_report_abs(ts->input_dev, ABS_MT_TOUCH_MINOR, ts->coord[t_id].minor);

						ts->coord[t_id].mcount++;
						break;
					default:
						input_dbg(true, &ts->client->dev,
								"%s: do not support coordinate action(%d)\n", __func__, ts->coord[t_id].action);
						break;
					}
				} else {
					input_dbg(true, &ts->client->dev,
							"%s: do not support coordinate type(%d)\n", __func__, ts->coord[t_id].ttype);
				}
			} else {
				input_err(true, &ts->client->dev, "%s: tid(%d) is out of range\n", __func__, t_id);
			}
			break;
		default:
			input_err(true, &ts->client->dev, "%s: unknown event %x %x %x %x %x %x\n", __func__,
					event_buff[0], event_buff[1], event_buff[2],
					event_buff[3], event_buff[4], event_buff[5]);
			break;
		}
out:
		curr_pos++;
		remain_event_count--;
	} while (remain_event_count >= 0);

	input_sync(ts->input_dev);
}

static irqreturn_t sec_ts_irq_thread(int irq, void *ptr)
{
	struct sec_ts_data *ts = (struct sec_ts_data *)ptr;

#ifdef CONFIG_SECURE_TOUCH
	if (secure_filter_interrupt(ts) == IRQ_HANDLED) {
		wait_for_completion_interruptible_timeout(&ts->secure_interrupt,
				msecs_to_jiffies(5 * MSEC_PER_SEC));

		input_info(true, &ts->client->dev,
				"%s: secure interrupt handled\n", __func__);

		return IRQ_HANDLED;
	}
#endif

	mutex_lock(&ts->eventlock);

	sec_ts_read_event(ts);

	mutex_unlock(&ts->eventlock);

	return IRQ_HANDLED;
}

static int sec_ts_pinctrl_configure(struct sec_ts_data *ts, bool enable)
{
	struct pinctrl_state *state;

	input_info(true, &ts->client->dev, "%s: %s\n", __func__, enable ? "ACTIVE" : "SUSPEND");

	if (enable) {
		state = pinctrl_lookup_state(ts->plat_data->pinctrl, "pmx_ts_active");
		if (IS_ERR(ts->plat_data->pinctrl))
			input_err(true, &ts->client->dev, "%s: could not get active pinstate\n", __func__);
	} else {
		state = pinctrl_lookup_state(ts->plat_data->pinctrl, "pmx_ts_suspend");
		if (IS_ERR(ts->plat_data->pinctrl))
			input_err(true, &ts->client->dev, "%s: could not get suspend pinstate\n", __func__);
	}

	if (!IS_ERR_OR_NULL(state))
		return pinctrl_select_state(ts->plat_data->pinctrl, state);

	return 0;

}

static int sec_ts_power(void *data, bool on)
{
	struct sec_ts_data *ts = (struct sec_ts_data *)data;
	const struct sec_ts_plat_data *pdata = ts->plat_data;
	struct regulator *regulator_dvdd = NULL;
	struct regulator *regulator_avdd = NULL;
	static bool enabled;
	int ret = 0;

	if (enabled == on)
		return ret;

	regulator_dvdd = regulator_get(NULL, pdata->regulator_dvdd);
	if (IS_ERR_OR_NULL(regulator_dvdd)) {
		input_err(true, &ts->client->dev, "%s: Failed to get %s regulator.\n",
				__func__, pdata->regulator_dvdd);
		ret = PTR_ERR(regulator_dvdd);
		goto error;
	}

	regulator_avdd = regulator_get(NULL, pdata->regulator_avdd);
	if (IS_ERR_OR_NULL(regulator_avdd)) {
		input_err(true, &ts->client->dev, "%s: Failed to get %s regulator.\n",
				__func__, pdata->regulator_avdd);
		ret = PTR_ERR(regulator_avdd);
		goto error;
	}

	if (on) {
		ret = regulator_enable(regulator_dvdd);
		if (ret) {
			input_err(true, &ts->client->dev, "%s: Failed to enable avdd: %d\n", __func__, ret);
		}

		sec_ts_delay(1);

		ret = regulator_enable(regulator_avdd);
		if (ret) {
			input_err(true, &ts->client->dev, "%s: Failed to enable vdd: %d\n", __func__, ret);
		}
	} else {
		regulator_disable(regulator_dvdd);
		regulator_disable(regulator_avdd);
	}

	enabled = on;

error:
	regulator_put(regulator_dvdd);
	regulator_put(regulator_avdd);

	return ret;
}

static int sec_ts_parse_dt(struct i2c_client *client)
{
	struct device *dev = &client->dev;
	struct sec_ts_plat_data *pdata = dev->platform_data;
	struct device_node *np = dev->of_node;
	u32 coords[2];
	int ret = 0;
	int count = 0;

	pdata->irq_gpio = of_get_named_gpio(np, "sec,irq_gpio", 0);
	if (gpio_is_valid(pdata->irq_gpio)) {
		ret = gpio_request_one(pdata->irq_gpio, GPIOF_DIR_IN, "sec,tsp_int");
		if (ret) {
			input_err(true, &client->dev, "%s: Unable to request tsp_int [%d]\n", __func__, pdata->irq_gpio);
			return -EINVAL;
		}
	} else {
		input_err(true, &client->dev, "%s: Failed to get irq gpio\n", __func__);
		return -EINVAL;
	}

	client->irq = gpio_to_irq(pdata->irq_gpio);

	pdata->irq_type = IRQF_TRIGGER_LOW | IRQF_ONESHOT;

	pdata->i2c_burstmax = 256;

	if (of_property_read_u32_array(np, "sec,max_coords", coords, 2)) {
		input_err(true, &client->dev, "%s: Failed to get max_coords property\n", __func__);
		return -EINVAL;
	}
	pdata->max_x = coords[0] - 1;
	pdata->max_y = coords[1] - 1;

	count = of_property_count_strings(np, "sec,firmware_name");
	if (count <= 0) {
		pdata->firmware_name = NULL;
	} else {
		of_property_read_string_index(np, "sec,firmware_name", 0, &pdata->firmware_name);
	}

	if (of_property_read_string_index(np, "sec,project_name", 0, &pdata->project_name))
		input_err(true, &client->dev, "%s: skipped to get project_name property\n", __func__);
	if (of_property_read_string_index(np, "sec,project_name", 1, &pdata->model_name))
		input_err(true, &client->dev, "%s: skipped to get model_name property\n", __func__);

	if (of_property_read_string(np, "sec,regulator_dvdd", &pdata->regulator_dvdd)) {
		input_err(true, dev, "%s: Failed to get regulator_dvdd name property\n", __func__);
		return -EINVAL;
	}

	if (of_property_read_string(np, "sec,regulator_avdd", &pdata->regulator_avdd)) {
		input_err(true, dev, "%s: Failed to get regulator_avdd name property\n", __func__);
		return -EINVAL;
	}

	pdata->power = sec_ts_power;

	pdata->regulator_boot_on = of_property_read_bool(np, "sec,regulator_boot_on");

	input_err(true, &client->dev, "%s: i2c buffer limit: %d, FW:%s(%d)\n",
			__func__, pdata->i2c_burstmax, pdata->firmware_name, count);

	return ret;
}

int sec_ts_read_information(struct sec_ts_data *ts)
{
	unsigned char data[13] = { 0 };
	int ret;

	memset(data, 0x0, 3);
	ret = sec_ts_i2c_read(ts, SEC_TS_READ_ID, data, 3);
	if (ret < 0) {
		input_err(true, &ts->client->dev,
				"%s: failed to read device id(%d)\n",
				__func__, ret);
		return ret;
	}

	input_info(true, &ts->client->dev,
			"%s: %X, %X, %X\n",
			__func__, data[0], data[1], data[2]);
	memset(data, 0x0, 11);
	ret = sec_ts_i2c_read(ts,  SEC_TS_READ_PANEL_INFO, data, 11);
	if (ret < 0) {
		input_err(true, &ts->client->dev,
				"%s: failed to read sub id(%d)\n",
				__func__, ret);
		return ret;
	}

	input_info(true, &ts->client->dev,
			"%s: nTX:%X, nRX:%X, rY:%d, rX:%d\n",
			__func__, data[8], data[9],
			(data[2] << 8) | data[3], (data[0] << 8) | data[1]);

	/* Set X,Y Resolution from IC information. */
	if (((data[0] << 8) | data[1]) > 0)
		ts->plat_data->max_x = ((data[0] << 8) | data[1]) - 1;

	if (((data[2] << 8) | data[3]) > 0)
		ts->plat_data->max_y = ((data[2] << 8) | data[3]) - 1;

	ts->tx_count = data[8];
	ts->rx_count = data[9];

	data[0] = 0;
	ret = sec_ts_i2c_read(ts, SEC_TS_READ_BOOT_STATUS, data, 1);
	if (ret < 0) {
		input_err(true, &ts->client->dev,
				"%s: failed to read sub id(%d)\n",
				__func__, ret);
		return ret;
	}

	input_info(true, &ts->client->dev,
			"%s: STATUS : %X\n",
			__func__, data[0]);

	memset(data, 0x0, 4);
	ret = sec_ts_i2c_read(ts, SEC_TS_READ_TS_STATUS, data, 4);
	if (ret < 0) {
		input_err(true, &ts->client->dev,
				"%s: failed to read sub id(%d)\n",
				__func__, ret);
		return ret;
	}

	input_info(true, &ts->client->dev,
			"%s: TOUCH STATUS : %02X, %02X, %02X, %02X\n",
			__func__, data[0], data[1], data[2], data[3]);
	ret = sec_ts_i2c_read(ts, SEC_TS_CMD_SET_TOUCHFUNCTION,  (u8 *)&(ts->touch_functions), 2);
	if (ret < 0) {
		input_err(true, &ts->client->dev,
				"%s: failed to read touch functions(%d)\n",
				__func__, ret);
		return ret;
	}

	input_info(true, &ts->client->dev,
			"%s: Functions : %02X\n",
			__func__, ts->touch_functions);

	return ret;
}

static void sec_ts_set_input_prop(struct sec_ts_data *ts, struct input_dev *dev, u8 propbit)
{
	static char sec_ts_phys[64] = { 0 };

	snprintf(sec_ts_phys, sizeof(sec_ts_phys), "%s/input1",
			dev->name);
	dev->phys = sec_ts_phys;
	dev->id.bustype = BUS_I2C;
	dev->dev.parent = &ts->client->dev;

	set_bit(EV_SYN, dev->evbit);
	set_bit(EV_KEY, dev->evbit);
	set_bit(EV_ABS, dev->evbit);
	set_bit(EV_SW, dev->evbit);
	set_bit(BTN_TOUCH, dev->keybit);
	set_bit(BTN_TOOL_FINGER, dev->keybit);

	set_bit(propbit, dev->propbit);
	set_bit(KEY_HOMEPAGE, dev->keybit);

	input_set_capability(dev, EV_SW, SW_GLOVE);

	input_set_abs_params(dev, ABS_MT_POSITION_X, 0, ts->plat_data->max_x, 0, 0);
	input_set_abs_params(dev, ABS_MT_POSITION_Y, 0, ts->plat_data->max_y, 0, 0);
	input_set_abs_params(dev, ABS_MT_TOUCH_MAJOR, 0, 255, 0, 0);
	input_set_abs_params(dev, ABS_MT_TOUCH_MINOR, 0, 255, 0, 0);

	if (propbit == INPUT_PROP_POINTER)
		input_mt_init_slots(dev, MAX_SUPPORT_TOUCH_COUNT, INPUT_MT_POINTER);
	else
		input_mt_init_slots(dev, MAX_SUPPORT_TOUCH_COUNT, INPUT_MT_DIRECT);

	input_set_drvdata(dev, ts);
}

#ifdef CONFIG_FB
static int fb_notifier_callback(struct notifier_block *self,
				unsigned long event,
				void *data);
#endif

static int sec_ts_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	struct sec_ts_data *ts;
	struct sec_ts_plat_data *pdata;
	int ret = 0;
	bool valid_firmware_integrity = false;
	unsigned char data[5] = { 0 };
	unsigned char deviceID[5] = { 0 };
	unsigned char result = 0;

	input_info(true, &client->dev, "%s\n", __func__);

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		input_err(true, &client->dev, "%s: EIO err!\n", __func__);
		return -EIO;
	}

	/* parse dt */
	if (client->dev.of_node) {
		pdata = devm_kzalloc(&client->dev,
				sizeof(struct sec_ts_plat_data), GFP_KERNEL);

		if (!pdata) {
			input_err(true, &client->dev, "%s: Failed to allocate platform data\n", __func__);
			goto error_allocate_pdata;
		}

		client->dev.platform_data = pdata;

		ret = sec_ts_parse_dt(client);
		if (ret) {
			input_err(true, &client->dev, "%s: Failed to parse dt\n", __func__);
			goto error_allocate_mem;
		}
	} else {
		pdata = client->dev.platform_data;
		if (!pdata) {
			input_err(true, &client->dev, "%s: No platform data found\n", __func__);
			goto error_allocate_pdata;
		}
	}

	if (!pdata->power) {
		input_err(true, &client->dev, "%s: No power contorl found\n", __func__);
		goto error_allocate_mem;
	}

	pdata->pinctrl = devm_pinctrl_get(&client->dev);
	if (IS_ERR(pdata->pinctrl))
		input_err(true, &client->dev, "%s: could not get pinctrl\n", __func__);

	ts = kzalloc(sizeof(struct sec_ts_data), GFP_KERNEL);
	if (!ts)
		goto error_allocate_mem;

	ts->client = client;
	ts->plat_data = pdata;
	ts->sec_ts_i2c_read = sec_ts_i2c_read;
	ts->sec_ts_i2c_write = sec_ts_i2c_write;
	ts->sec_ts_i2c_write_burst = sec_ts_i2c_write_burst;
	ts->sec_ts_i2c_read_bulk = sec_ts_i2c_read_bulk;
	ts->i2c_burstmax = pdata->i2c_burstmax;
	INIT_DELAYED_WORK(&ts->work_read_info, sec_ts_read_info_work);

	i2c_set_clientdata(client, ts);

	ts->input_dev = input_allocate_device();
	if (!ts->input_dev) {
		input_err(true, &ts->client->dev, "%s: allocate device err!\n", __func__);
		ret = -ENOMEM;
		goto err_allocate_input_dev;
	}

	ts->touch_count = 0;

	mutex_init(&ts->lock);
	mutex_init(&ts->device_mutex);
	mutex_init(&ts->i2c_mutex);
	mutex_init(&ts->eventlock);

	wake_lock_init(&ts->wakelock, WAKE_LOCK_SUSPEND, "tsp_wakelock");

	input_info(true, &client->dev, "%s: init resource\n", __func__);

	sec_ts_pinctrl_configure(ts, true);

	/* power enable */
	sec_ts_power(ts, true);
	if (!pdata->regulator_boot_on)
		sec_ts_delay(70);
	ts->power_status = SEC_TS_STATE_POWER_ON;

	sec_ts_wait_for_ready(ts, SEC_TS_ACK_BOOT_COMPLETE);

	input_info(true, &client->dev, "%s: power enable\n", __func__);

	ret = sec_ts_i2c_read(ts, SEC_TS_READ_DEVICE_ID, deviceID, 5);
	if (ret < 0)
		input_err(true, &ts->client->dev, "%s: failed to read device ID(%d)\n", __func__, ret);
	else
		input_info(true, &ts->client->dev,
				"%s: TOUCH DEVICE ID : %02X, %02X, %02X, %02X, %02X\n", __func__,
				deviceID[0], deviceID[1], deviceID[2], deviceID[3], deviceID[4]);

	ret = sec_ts_i2c_read(ts, SEC_TS_READ_FIRMWARE_INTEGRITY, &result, 1);
	if (ret < 0) {
		input_err(true, &ts->client->dev, "%s: failed to integrity check (%d)\n", __func__, ret);
	} else {
		if (result & 0x80) {
			valid_firmware_integrity = true;
		} else if (result & 0x40) {
			valid_firmware_integrity = false;
			input_err(true, &ts->client->dev, "%s: invalid firmware (0x%x)\n", __func__, result);
		} else {
			valid_firmware_integrity = false;
			input_err(true, &ts->client->dev, "%s: invalid integrity result (0x%x)\n", __func__, result);
		}
	}

	ret = sec_ts_i2c_read(ts, SEC_TS_READ_BOOT_STATUS, &data[0], 1);
	if (ret < 0) {
		input_err(true, &ts->client->dev,
				"%s: failed to read sub id(%d)\n",
				__func__, ret);
	} else {
		ret = sec_ts_i2c_read(ts, SEC_TS_READ_TS_STATUS, &data[1], 4);
		if (ret < 0) {
			input_err(true, &ts->client->dev,
					"%s: failed to touch status(%d)\n",
					__func__, ret);
		}
	}
	input_info(true, &ts->client->dev,
			"%s: TOUCH STATUS : %02X || %02X, %02X, %02X, %02X\n",
			__func__, data[0], data[1], data[2], data[3], data[4]);

	if (data[0] == SEC_TS_STATUS_BOOT_MODE)
		ts->checksum_result = 1;

	input_info(true, &ts->client->dev, "%s: fw update on probe disabled!\n", __func__);

	ret = sec_ts_read_information(ts);
	if (ret < 0) {
		input_err(true, &ts->client->dev, "%s: fail to read information 0x%x\n", __func__, ret);
		goto err_init;
	}

	ts->touch_functions |= SEC_TS_DEFAULT_ENABLE_BIT_SETFUNC;
	ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SET_TOUCHFUNCTION, (u8 *)&ts->touch_functions, 2);
	if (ret < 0)
		input_err(true, &ts->client->dev, "%s: Failed to send touch func_mode command", __func__);

	/* Sense_on */
	ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SENSE_ON, NULL, 0);
	if (ret < 0) {
		input_err(true, &ts->client->dev, "%s: fail to write Sense_on\n", __func__);
		goto err_init;
	}

	ts->pFrame = kzalloc(ts->tx_count * ts->rx_count * 2, GFP_KERNEL);
	if (!ts->pFrame) {
		ret = -ENOMEM;
		goto err_allocate_frame;
	}

	ts->input_dev->name = "sec_touchscreen";
	sec_ts_set_input_prop(ts, ts->input_dev, INPUT_PROP_DIRECT);
#ifdef USE_OPEN_CLOSE
	ts->input_dev->open = sec_ts_input_open;
	ts->input_dev->close = sec_ts_input_close;
#endif
	ts->input_dev_touch = ts->input_dev;

	ret = input_register_device(ts->input_dev);
	if (ret) {
		input_err(true, &ts->client->dev, "%s: Unable to register %s input device\n", __func__, ts->input_dev->name);
		goto err_input_register_device;
	}

	input_info(true, &ts->client->dev, "%s: request_irq = %d\n", __func__, client->irq);

	ret = request_threaded_irq(client->irq, NULL, sec_ts_irq_thread,
			ts->plat_data->irq_type, SEC_TS_I2C_NAME, ts);
	if (ret < 0) {
		input_err(true, &ts->client->dev, "%s: Unable to request threaded irq\n", __func__);
		goto err_irq;
	}

#ifdef CONFIG_FB
	ts->fb_notif.notifier_call = fb_notifier_callback;
	if (fb_register_client(&ts->fb_notif))
		pr_err("%s: could not create fb notifier\n", __func__);
#endif

#ifdef CONFIG_SECURE_TOUCH
	if (sysfs_create_group(&ts->input_dev->dev.kobj, &secure_attr_group) < 0)
		input_err(true, &ts->client->dev, "%s: do not make secure group\n", __func__);
	else
		secure_touch_init(ts);
#endif

	device_init_wakeup(&client->dev, true);

	schedule_delayed_work(&ts->work_read_info, msecs_to_jiffies(50));

	input_err(true, &ts->client->dev, "%s: done\n", __func__);

#ifdef CONFIG_SEC_TS_WAKE_GESTURES
	sec_ts_wake_gestures_init(ts);
#endif

	return 0;

err_irq:
err_input_register_device:
	kfree(ts->pFrame);
err_allocate_frame:
err_init:
	wake_lock_destroy(&ts->wakelock);
	sec_ts_power(ts, false);
err_allocate_input_dev:
	kfree(ts);

error_allocate_mem:
	if (gpio_is_valid(pdata->irq_gpio))
		gpio_free(pdata->irq_gpio);

error_allocate_pdata:
	if (ret == -ECONNREFUSED)
		sec_ts_delay(100);
	ret = -ENODEV;

	input_err(true, &client->dev, "%s: failed(%d)\n", __func__, ret);
	return ret;
}

void sec_ts_unlocked_release_all_finger(struct sec_ts_data *ts)
{
	int i;

	for (i = 0; i < MAX_SUPPORT_TOUCH_COUNT; i++) {
		input_mt_slot(ts->input_dev, i);
		input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, false);

		if ((ts->coord[i].action == SEC_TS_COORDINATE_ACTION_PRESS) ||
				(ts->coord[i].action == SEC_TS_COORDINATE_ACTION_MOVE))
			ts->coord[i].action = SEC_TS_COORDINATE_ACTION_RELEASE;

		ts->coord[i].mcount = 0;
		ts->coord[i].palm_count = 0;
	}

	input_mt_slot(ts->input_dev, 0);

	input_report_key(ts->input_dev, BTN_TOUCH, false);
	input_report_key(ts->input_dev, BTN_TOOL_FINGER, false);
	input_report_switch(ts->input_dev, SW_GLOVE, false);
	ts->touchkey_glove_mode_status = false;
	ts->touch_count = 0;
	ts->check_multi = 0;

	input_report_key(ts->input_dev, KEY_HOMEPAGE, 0);
	input_sync(ts->input_dev);

}

void sec_ts_locked_release_all_finger(struct sec_ts_data *ts)
{
	int i;

	mutex_lock(&ts->eventlock);

	for (i = 0; i < MAX_SUPPORT_TOUCH_COUNT; i++) {
		input_mt_slot(ts->input_dev, i);
		input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, false);

		if ((ts->coord[i].action == SEC_TS_COORDINATE_ACTION_PRESS) ||
				(ts->coord[i].action == SEC_TS_COORDINATE_ACTION_MOVE))
			ts->coord[i].action = SEC_TS_COORDINATE_ACTION_RELEASE;

		ts->coord[i].mcount = 0;
		ts->coord[i].palm_count = 0;
	}

	input_mt_slot(ts->input_dev, 0);

	input_report_key(ts->input_dev, BTN_TOUCH, false);
	input_report_key(ts->input_dev, BTN_TOOL_FINGER, false);
	input_report_switch(ts->input_dev, SW_GLOVE, false);
	ts->touchkey_glove_mode_status = false;
	ts->touch_count = 0;
	ts->check_multi = 0;

	input_report_key(ts->input_dev, KEY_HOMEPAGE, 0);
	input_sync(ts->input_dev);

	mutex_unlock(&ts->eventlock);

}

static void sec_ts_read_info_work(struct work_struct *work)
{
	struct sec_ts_data *ts = container_of(work, struct sec_ts_data,
			work_read_info.work);

	ts->nv = get_tsp_nvm_data(ts, SEC_TS_NVM_OFFSET_FAC_RESULT);
	ts->cal_count = get_tsp_nvm_data(ts, SEC_TS_NVM_OFFSET_CAL_COUNT);

	input_info(true, &ts->client->dev, "%s: fac_nv:%02X, cal_count:%02X\n",
			__func__, ts->nv, ts->cal_count);

	sec_ts_run_rawdata_all(ts, false);

}

#ifdef USE_OPEN_CLOSE
static int sec_ts_input_open(struct input_dev *dev)
{
	struct sec_ts_data *ts = input_get_drvdata(dev);
	int ret;

#ifdef CONFIG_SECURE_TOUCH
	secure_touch_stop(ts, 0);
#endif

	ret = sec_ts_start_device(ts);
	if (ret < 0)
		input_err(true, &ts->client->dev, "%s: Failed to start device\n", __func__);

	return 0;
}

static void sec_ts_input_close(struct input_dev *dev)
{
	struct sec_ts_data *ts = input_get_drvdata(dev);

#ifdef MINORITY_REPORT
	minority_report_sync_latest_value(ts);
#endif

#ifdef CONFIG_SECURE_TOUCH
	secure_touch_stop(ts, 1);
#endif

	sec_ts_stop_device(ts);
}
#endif

static int sec_ts_remove(struct i2c_client *client)
{
	struct sec_ts_data *ts = i2c_get_clientdata(client);

	input_info(true, &ts->client->dev, "%s\n", __func__);

	cancel_delayed_work_sync(&ts->work_read_info);
	flush_delayed_work(&ts->work_read_info);

	disable_irq_nosync(ts->client->irq);
	free_irq(ts->client->irq, ts);
	input_info(true, &ts->client->dev, "%s: irq disabled\n", __func__);

	device_init_wakeup(&client->dev, false);
	wake_lock_destroy(&ts->wakelock);

#ifdef CONFIG_SEC_TS_WAKE_GESTURES
	sec_ts_wake_gestures_exit();
#endif

	ts->input_dev = ts->input_dev_touch;
	input_mt_destroy_slots(ts->input_dev);
	input_unregister_device(ts->input_dev);

#ifdef CONFIG_FB
	fb_unregister_client(&ts->fb_notif);
#endif

#ifdef CONFIG_SECURE_TOUCH
	secure_touch_remove(ts);
#endif

	ts->input_dev = NULL;
	ts->input_dev_touch = NULL;
	ts->plat_data->power(ts, false);

	kfree(ts);
	return 0;
}

static void sec_ts_shutdown(struct i2c_client *client)
{
	struct sec_ts_data *ts = i2c_get_clientdata(client);

	input_info(true, &ts->client->dev, "%s\n", __func__);

	sec_ts_remove(client);
}

int sec_ts_stop_device(struct sec_ts_data *ts)
{
	mutex_lock(&ts->device_mutex);

	if (ts->power_status == SEC_TS_STATE_POWER_OFF) {
		input_err(true, &ts->client->dev, "%s: already power off\n", __func__);
		goto out;
	}

	ts->power_status = SEC_TS_STATE_POWER_OFF;

	disable_irq(ts->client->irq);
	sec_ts_locked_release_all_finger(ts);

	ts->plat_data->power(ts, false);

	sec_ts_pinctrl_configure(ts, false);

out:
	mutex_unlock(&ts->device_mutex);
	return 0;
}

int sec_ts_start_device(struct sec_ts_data *ts)
{
	int ret = -1;

	sec_ts_pinctrl_configure(ts, true);

	mutex_lock(&ts->device_mutex);

	if (ts->power_status == SEC_TS_STATE_POWER_ON) {
		input_err(true, &ts->client->dev, "%s: already power on\n", __func__);
		goto out;
	}

	sec_ts_locked_release_all_finger(ts);

	ts->plat_data->power(ts, true);
	ts->power_status = SEC_TS_STATE_POWER_ON;
	ts->touch_noise_status = 0;

	ret = sec_ts_wait_for_ready(ts, SEC_TS_ACK_BOOT_COMPLETE);
	if (ret < 0) {
		input_err(true, &ts->client->dev,
				"%s: Failed to wait_for_ready\n", __func__);
		goto err;
	}

	ts->touch_functions = ts->touch_functions | SEC_TS_DEFAULT_ENABLE_BIT_SETFUNC;
	ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SET_TOUCHFUNCTION, (u8 *)&ts->touch_functions, 2);
	if (ret < 0) {
		input_err(true, &ts->client->dev,
				"%s: Failed to send touch function command\n", __func__);
		goto err;
	}

err:
	/* Sense_on */
	ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SENSE_ON, NULL, 0);
	if (ret < 0)
		input_err(true, &ts->client->dev, "%s: fail to write Sense_on\n", __func__);

	enable_irq(ts->client->irq);

out:
	mutex_unlock(&ts->device_mutex);
	return ret;
}

void sec_ts_suspend(struct input_dev *dev)
{
#ifdef USE_OPEN_CLOSE
	struct sec_ts_data *ts = input_get_drvdata(dev);
	int retval;

#ifdef CONFIG_SEC_TS_WAKE_GESTURES
	if (dt2w_switch_changed) {
		dt2w_switch = dt2w_switch_temp;
		dt2w_switch_changed = false;
	}

	if (dt2w_switch) {
		enable_irq_wake(ts->client->irq);
		sec_ts_locked_release_all_finger(ts);
		goto out;
	}
#endif

	retval = mutex_lock_interruptible(&ts->input_dev->mutex);
	if (retval) {
		input_err(true, &ts->client->dev,
				"%s : mutex error\n", __func__);
		goto out;
	}

	if (!ts->screen_off)
		ts->input_dev->close(ts->input_dev);

	mutex_unlock(&ts->input_dev->mutex);
out:
	ts->screen_off = true;
	return;
#endif
}

void sec_ts_resume(struct input_dev *dev)
{
#ifdef USE_OPEN_CLOSE
	struct sec_ts_data *ts = input_get_drvdata(dev);
	int retval;

#ifdef CONFIG_SEC_TS_WAKE_GESTURES
	if (dt2w_switch) {
		disable_irq_wake(ts->client->irq);
		sec_ts_locked_release_all_finger(ts);
		goto out;
	} 
#endif
	
	retval = mutex_lock_interruptible(&ts->input_dev->mutex);
	if (retval) {
		input_err(true, &ts->client->dev,
				"%s : mutex error\n", __func__);
		goto out;
	}
	if (ts->screen_off)
		ts->input_dev->open(ts->input_dev);

	mutex_unlock(&ts->input_dev->mutex);
out:
	ts->screen_off = false;
	return;
#endif
}

#ifdef CONFIG_FB
static int fb_notifier_callback(struct notifier_block *self,
				unsigned long event,
				void *data)
{
	struct fb_event *evdata = data;
	struct sec_ts_data *tc_data = container_of(self, struct sec_ts_data, fb_notif);

	if (evdata && evdata->data && event == FB_EVENT_BLANK) {
		int *blank = evdata->data;
		switch (*blank) {
		case FB_BLANK_UNBLANK:
				sec_ts_resume(tc_data->input_dev);
			break;
		case FB_BLANK_POWERDOWN:
		        sec_ts_suspend(tc_data->input_dev);
			break;
		}
	}

	return 0;
}
#endif

static const struct i2c_device_id sec_ts_id[] = {
	{ SEC_TS_I2C_NAME, 0 },
	{ },
};

#ifdef CONFIG_OF
static const struct of_device_id sec_ts_match_table[] = {
	{ .compatible = "sec,sec_ts",},
	{ },
};
#else
#define sec_ts_match_table NULL
#endif

static struct i2c_driver sec_ts_driver = {
	.probe		= sec_ts_probe,
	.remove		= sec_ts_remove,
	.shutdown	= sec_ts_shutdown,
	.id_table	= sec_ts_id,
	.driver = {
		.owner	= THIS_MODULE,
		.name	= SEC_TS_I2C_NAME,
#ifdef CONFIG_OF
		.of_match_table = sec_ts_match_table,
#endif
	},
};

static int __init sec_ts_init(void)
{
	pr_err("%s %s\n", SECLOG, __func__);

	return i2c_add_driver(&sec_ts_driver);
}

static void __exit sec_ts_exit(void)
{
	i2c_del_driver(&sec_ts_driver);
}

MODULE_AUTHOR("Hyobae, Ahn<hyobae.ahn@samsung.com>");
MODULE_DESCRIPTION("Samsung Electronics TouchScreen driver");
MODULE_LICENSE("GPL");

module_init(sec_ts_init);
module_exit(sec_ts_exit);
