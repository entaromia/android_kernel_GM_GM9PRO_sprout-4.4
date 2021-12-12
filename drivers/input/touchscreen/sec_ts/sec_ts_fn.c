/* drivers/input/touchscreen/sec_ts_fn.c
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

#include "include/sec_ts.h"
#include "include/sec_ts_fac_spec.h"

static int execute_selftest(struct sec_ts_data *ts, bool save_result);

int sec_ts_fix_tmode(struct sec_ts_data *ts, u8 mode, u8 state)
{
	int ret;
	u8 onoff[1] = {STATE_MANAGE_OFF};
	u8 tBuff[2] = { mode, state };

	input_info(true, &ts->client->dev, "%s\n", __func__);

	ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_STATEMANAGE_ON, onoff, 1);
	sec_ts_delay(20);

	ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_CHG_SYSMODE, tBuff, sizeof(tBuff));
	sec_ts_delay(20);

	return ret;
}

int sec_ts_release_tmode(struct sec_ts_data *ts)
{
	int ret;
	u8 onoff[1] = {STATE_MANAGE_ON};

	input_info(true, &ts->client->dev, "%s\n", __func__);

	ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_STATEMANAGE_ON, onoff, 1);
	sec_ts_delay(20);

	return ret;
}

static int sec_ts_get_boca_spec(struct sec_ts_data *ts)
{
	cm_delta_xdir = cm_delta_xdir_125boca;
	cm_delta_ydir = cm_delta_ydir_125boca;
	pre_cm_delta_xdir = pre_cm_delta_xdir_125boca;
	pre_cm_delta_ydir = pre_cm_delta_ydir_125boca;
	cm_delta_avg_xdir = cm_delta_avg_xdir_125boca;
	cm_delta_avg_ydir = cm_delta_avg_ydir_125boca;

	return 0;
}

static void sec_ts_cm_spec_over_check(struct sec_ts_data *ts)
{
	int i = 0;
	int j = 0;
	int by, bx, bpos, tpos1, tpos2;
	int vb, vt1, vt2, gapy, gapx, specover_count_x, specover_count_y;
	int xdir_cm_avg[30], ydir_cm_avg[50];
	u8 spec_out_nv = 0x00;
	int data[30];
	int fail_list[6];

	input_info(true, &ts->client->dev, "%s\n", __func__);

	if (sec_ts_get_boca_spec(ts) < 0)
		return;

	input_info(true, &ts->client->dev,
		"rx_max(%d) tx_max(%d)\n", ts->rx_count, ts->tx_count);

	for (i = 0; i < ts->rx_count; i++)
		ydir_cm_avg[i] = 0;
	for (i = 0; i < ts->tx_count; i++)
		xdir_cm_avg[i] = 0;

	specover_count_x = 0;
	specover_count_y = 0;
	for (i = 0; i < 6; i++)
		fail_list[i] = 0;

	input_info(true, &ts->client->dev, "gapX TX\n");

	for (i = 0; i < ts->rx_count; i++) {
		for (j = 0; j < ts->tx_count - 1; j++) {
			bx = i;
			by = j;

			bpos = (j * ts->rx_count) + i;
			tpos2 = ((j + 1) * ts->rx_count) + i;

			vb = ts->pFrame[bpos];
			vt2 = ts->pFrame[tpos2];

			if (vb > vt2)
				gapx = 100 - (vt2 * 100 / vb);
			else
				gapx = 100 - (vb * 100 / vt2);

			/* gapy is  tx delta, a raw of tx delta has to be saved at that row */
			/* bx is  row, by is column, take care */
			ydir_cm_avg[bx] += gapx;
			data[by] = gapx;

			/* take care  index of x,y.  it is inverted. */
			if (gapx > cm_delta_xdir[bx][by]) {
				specover_count_x++;
				spec_out_nv |= SEC_TS_CM_SPEC_OUT_TX_NODE;
				fail_list[1] = by;
				fail_list[2] = bx;
				input_raw_info(true, &ts->client->dev,
						"y(%2d) x(%2d) gapx(%d) cm_spec xdir(%d)\n",
						bx, by, gapx, cm_delta_xdir[bx][by]);
				}
		}
	}

	input_info(true, &ts->client->dev, "gapY RX\n");

	for (i = 0; i < ts->rx_count - 1; i++) {
		for (j = 0; j < ts->tx_count; j++) {
			bx = i;
			by = j;

			bpos = (j * ts->rx_count) + i;
			tpos1 = (j * ts->rx_count) + (i + 1);

			vb = ts->pFrame[bpos];
			vt1 = ts->pFrame[tpos1];

			if (vb > vt1)
				gapy = 100 - (vt1 * 100 / vb);
			else
				gapy = 100 - (vb * 100 / vt1);

			xdir_cm_avg[by] += gapy;
			data[by] = gapy;

			/* take care  index of x,y.  it is inverted. */
			if (gapy > cm_delta_ydir[bx][by]) {
				specover_count_y++;
				spec_out_nv |= SEC_TS_CM_SPEC_OUT_RX_NODE;
				fail_list[4] = by;
				fail_list[5] = bx;
				input_raw_info(true, &ts->client->dev,
						"y(%2d) x(%2d) gapy(%d) cm_spec ydir(%d)\n",
						bx, by, gapy, cm_delta_ydir[bx][by]);
				}
		}
	}

	for (i = 0; i < ts->rx_count; i++) {
		if ((ydir_cm_avg[i] / (ts->tx_count - 1)) > cm_delta_avg_ydir[i]) {
			/*specover_count++;*/
			spec_out_nv |= SEC_TS_CM_SPEC_OUT_RX_AVG;
		}
	}
	for (i = 0; i < ts->tx_count; i++) {
		if ((xdir_cm_avg[i] / (ts->rx_count - 1)) > cm_delta_avg_xdir[i]) {
			/*specover_count++;*/
			spec_out_nv |= SEC_TS_CM_SPEC_OUT_TX_AVG;
		}
	}
	fail_list[0] = specover_count_x;
	fail_list[3] = specover_count_y;

	for (i = 0; i < 6; i++)
		ts->cm_fail_list[i] = fail_list[i];

	ts->cm_specover = specover_count_x + specover_count_y;
	input_raw_info(true, &ts->client->dev,
			"spec out x(%d) spec out y(%d) nv(0x%02X)\n",
			specover_count_x, specover_count_y, spec_out_nv);
}

static int sec_ts_read_frame(struct sec_ts_data *ts, u8 type, short *min,
				short *max, bool save_result)
{
	unsigned int readbytes = 0xFF;
	unsigned char *pRead = NULL;
	u8 mode = TYPE_INVALID_DATA;
	int ret = 0;
	int i = 0;
	int j = 0;
	short *temp = NULL;

	input_raw_info(true, &ts->client->dev, "%s: type %d\n", __func__, type);

	/* set data length, allocation buffer memory */
	readbytes = ts->rx_count * ts->tx_count * 2;

	pRead = kzalloc(readbytes, GFP_KERNEL);
	if (!pRead)
		return -ENOMEM;

	/* set OPCODE and data type */
	ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_MUTU_RAW_TYPE, &type, 1);
	if (ret < 0) {
		input_err(true, &ts->client->dev, "%s: Set rawdata type failed\n", __func__);
		goto ErrorExit;
	}

	sec_ts_delay(50);

	if (type == TYPE_OFFSET_DATA_SDC) {
		/* excute selftest for real cap offset data, because real cap data is not memory data in normal touch. */
		char para = TO_TOUCH_MODE;

		disable_irq(ts->client->irq);

		execute_selftest(ts, save_result);

		ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_SET_POWER_MODE, &para, 1);
		if (ret < 0) {
			input_err(true, &ts->client->dev, "%s: Set rawdata type failed\n", __func__);
			enable_irq(ts->client->irq);
			goto ErrorRelease;
		}

		enable_irq(ts->client->irq);
	}

	/* read data */
	ret = ts->sec_ts_i2c_read(ts, SEC_TS_READ_TOUCH_RAWDATA, pRead, readbytes);
	if (ret < 0) {
		input_err(true, &ts->client->dev, "%s: read rawdata failed!\n", __func__);
		goto ErrorRelease;
	}

	memset(ts->pFrame, 0x00, readbytes);

	for (i = 0; i < readbytes; i += 2)
		ts->pFrame[i / 2] = pRead[i + 1] + (pRead[i] << 8);

	*min = *max = ts->pFrame[0];

	if (type == TYPE_OFFSET_DATA_SDC)
		sec_ts_cm_spec_over_check(ts);

	temp = kzalloc(readbytes, GFP_KERNEL);
	if (!temp)
		goto ErrorRelease;

	memcpy(temp, ts->pFrame, ts->tx_count * ts->rx_count * 2);
	memset(ts->pFrame, 0x00, ts->tx_count * ts->rx_count * 2);

	for (i = 0; i < ts->tx_count; i++) {
		for (j = 0; j < ts->rx_count; j++)
			ts->pFrame[(j * ts->tx_count) + i] = temp[(i * ts->rx_count) + j];
	}

	kfree(temp);

ErrorRelease:
	/* release data monitory (unprepare AFE data memory) */
	ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_MUTU_RAW_TYPE, &mode, 1);
	if (ret < 0)
		input_err(true, &ts->client->dev, "%s: Set rawdata type failed\n", __func__);

ErrorExit:
	kfree(pRead);

	return ret;
}

static void sec_ts_print_channel(struct sec_ts_data *ts)
{
	unsigned char *pStr = NULL;
	unsigned char pTmp[16] = { 0 };
	int i = 0, j = 0, k = 0;

	if (!ts->tx_count)
		return;

	pStr = vzalloc(7 * (ts->tx_count + 1));
	if (!pStr)
		return;

	memset(pStr, 0x0, 7 * (ts->tx_count + 1));
	snprintf(pTmp, sizeof(pTmp), " TX");
	strncat(pStr, pTmp, 7 * ts->tx_count);

	for (k = 0; k < ts->tx_count; k++) {
		snprintf(pTmp, sizeof(pTmp), "    %02d", k);
		strncat(pStr, pTmp, 7 * ts->tx_count);
	}
	input_raw_info(true, &ts->client->dev, "%s\n", pStr);

	memset(pStr, 0x0, 7 * (ts->tx_count + 1));
	snprintf(pTmp, sizeof(pTmp), " +");
	strncat(pStr, pTmp, 7 * ts->tx_count);

	for (k = 0; k < ts->tx_count; k++) {
		snprintf(pTmp, sizeof(pTmp), "------");
		strncat(pStr, pTmp, 7 * ts->tx_count);
	}
	input_raw_info(true, &ts->client->dev, "%s\n", pStr);

	memset(pStr, 0x0, 7 * (ts->tx_count + 1));
	snprintf(pTmp, sizeof(pTmp), " | ");
	strncat(pStr, pTmp, 7 * ts->tx_count);

	for (i = 0; i < (ts->tx_count + ts->rx_count) * 2; i += 2) {
		if (j == ts->tx_count) {
			input_raw_info(true, &ts->client->dev, "%s\n", pStr);
			input_raw_info(true, &ts->client->dev, "\n");
			memset(pStr, 0x0, 7 * (ts->tx_count + 1));
			snprintf(pTmp, sizeof(pTmp), " RX");
			strncat(pStr, pTmp, 7 * ts->tx_count);

			for (k = 0; k < ts->tx_count; k++) {
				snprintf(pTmp, sizeof(pTmp), "    %02d", k);
				strncat(pStr, pTmp, 7 * ts->tx_count);
			}

			input_raw_info(true, &ts->client->dev, "%s\n", pStr);

			memset(pStr, 0x0, 7 * (ts->tx_count + 1));
			snprintf(pTmp, sizeof(pTmp), " +");
			strncat(pStr, pTmp, 7 * ts->tx_count);

			for (k = 0; k < ts->tx_count; k++) {
				snprintf(pTmp, sizeof(pTmp), "------");
				strncat(pStr, pTmp, 7 * ts->tx_count);
			}
			input_raw_info(true, &ts->client->dev, "%s\n", pStr);

			memset(pStr, 0x0, 7 * (ts->tx_count + 1));
			snprintf(pTmp, sizeof(pTmp), " | ");
			strncat(pStr, pTmp, 7 * ts->tx_count);
		} else if (j && !(j % ts->tx_count)) {
			input_raw_info(true, &ts->client->dev, "%s\n", pStr);
			memset(pStr, 0x0, 7 * (ts->tx_count + 1));
			snprintf(pTmp, sizeof(pTmp), " | ");
			strncat(pStr, pTmp, 7 * ts->tx_count);
		}

		snprintf(pTmp, sizeof(pTmp), " %5d", ts->pFrame[j]);
		strncat(pStr, pTmp, 7 * ts->tx_count);

		j++;
	}
	input_raw_info(true, &ts->client->dev, "%s\n", pStr);
	vfree(pStr);
}

static int sec_ts_read_channel(struct sec_ts_data *ts, u8 type,
				short *min, short *max, bool save_result)
{
	unsigned char *pRead = NULL;
	u8 mode = TYPE_INVALID_DATA;
	int ret = 0;
	int ii = 0;
	int jj = 0;
	unsigned int data_length = (ts->tx_count + ts->rx_count) * 2;
	u8 w_data;

	input_raw_info(true, &ts->client->dev, "%s: type %d\n", __func__, type);

	pRead = kzalloc(data_length, GFP_KERNEL);
	if (!pRead)
		return -ENOMEM;

	/* set OPCODE and data type */
	w_data = type;

	ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_SELF_RAW_TYPE, &w_data, 1);
	if (ret < 0) {
		input_err(true, &ts->client->dev, "%s: Set rawdata type failed\n", __func__);
		goto out_read_channel;
	}

	sec_ts_delay(50);

	if (type == TYPE_OFFSET_DATA_SDC) {
		/* excute selftest for real cap offset data, because real cap data is not memory data in normal touch. */
		char para = TO_TOUCH_MODE;
		disable_irq(ts->client->irq);
		execute_selftest(ts, save_result);
		ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_SET_POWER_MODE, &para, 1);
		if (ret < 0) {
			input_err(true, &ts->client->dev, "%s: set rawdata type failed!\n", __func__);
			enable_irq(ts->client->irq);
			goto err_read_data;
		}
		enable_irq(ts->client->irq);
		/* end */
	}

	/* read data */
	ret = ts->sec_ts_i2c_read(ts, SEC_TS_READ_TOUCH_SELF_RAWDATA, pRead, data_length);
	if (ret < 0) {
		input_err(true, &ts->client->dev, "%s: read rawdata failed!\n", __func__);
		goto err_read_data;
	}

	/* clear all pFrame data */
	memset(ts->pFrame, 0x00, data_length);

	for (ii = 0; ii < data_length; ii += 2) {
		ts->pFrame[jj] = ((pRead[ii] << 8) | pRead[ii + 1]);

		if (ii == 0)
			*min = *max = ts->pFrame[jj];

		*min = min(*min, ts->pFrame[jj]);
		*max = max(*max, ts->pFrame[jj]);

		jj++;
	}

	sec_ts_print_channel(ts);

err_read_data:
	/* release data monitory (unprepare AFE data memory) */
	ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_SELF_RAW_TYPE, &mode, 1);
	if (ret < 0)
		input_err(true, &ts->client->dev, "%s: Set rawdata type failed\n", __func__);

out_read_channel:
	kfree(pRead);

	return ret;
}

/*
 * sec_ts_run_rawdata_all : read all raw data
 *
 * when you want to read full raw data (full_read : true)
 * "mutual/self 3, 5, 29, 1, 19" data will be saved in log
 *
 * otherwise, (full_read : false, especially on boot time)
 * only "mutual 3, 5, 29" data will be saved in log
 */
void sec_ts_run_rawdata_all(struct sec_ts_data *ts, bool full_read)
{
	short min, max;
	int ret, i, read_num;
	u8 test_type[5] = {TYPE_AMBIENT_DATA, TYPE_DECODED_DATA,
		TYPE_SIGNAL_DATA, TYPE_OFFSET_DATA_SEC, TYPE_OFFSET_DATA_SDC};

	input_raw_info(true, &ts->client->dev,
			"%s: start (noise:%d, wet:%d)##\n",
			__func__, ts->touch_noise_status, ts->wet_mode);

	ret = sec_ts_fix_tmode(ts, TOUCH_SYSTEM_MODE_TOUCH, TOUCH_MODE_STATE_TOUCH);
	if (ret < 0) {
		input_err(true, &ts->client->dev, "%s: failed to fix tmode\n",
				__func__);
		goto out;
	}

	if (full_read) {
		read_num = 5;
	} else {
		read_num = 3;
		test_type[read_num - 1] = TYPE_OFFSET_DATA_SDC;
	}

	for (i = 0; i < read_num; i++) {
		ret = sec_ts_read_frame(ts, test_type[i], &min, &max, false);
		if (ret < 0)
			input_raw_info(true, &ts->client->dev,
					"%s: mutual %d : error ## ret:%d\n",
					__func__, test_type[i], ret);
		else
			input_raw_info(true, &ts->client->dev,
					"%s: mutual %d : Max/Min %d,%d ##\n",
					__func__, test_type[i], max, min);
		sec_ts_delay(20);

#ifdef MINORITY_REPORT
		if (test_type[i] == TYPE_AMBIENT_DATA) {
			minority_report_calculate_rawdata(ts);
		} else if (test_type[i] == TYPE_OFFSET_DATA_SDC) {
			minority_report_calculate_ito(ts);
			minority_report_sync_latest_value(ts);
		}
#endif
		if (full_read) {
			ret = sec_ts_read_channel(ts, test_type[i], &min, &max, false);
			if (ret < 0)
				input_raw_info(true, &ts->client->dev,
						"%s: self %d : error ## ret:%d\n",
						__func__, test_type[i], ret);
			else
				input_raw_info(true, &ts->client->dev,
						"%s: self %d : Max/Min %d,%d ##\n",
						__func__, test_type[i], max, min);
			sec_ts_delay(20);
		}
	}
	sec_ts_release_tmode(ts);

out:
	input_raw_info(true, &ts->client->dev, "%s: ito : %02X %02X %02X %02X\n",
			__func__, ts->ito_test[0], ts->ito_test[1]
			, ts->ito_test[2], ts->ito_test[3]);

	input_raw_info(true, &ts->client->dev, "%s: done (noise:%d, wet:%d)##\n",
			__func__, ts->touch_noise_status, ts->wet_mode);

	sec_ts_locked_release_all_finger(ts);
}

int get_tsp_nvm_data(struct sec_ts_data *ts, u8 offset)
{
	char buff[2] = { 0 };
	int ret;

	/* SENSE OFF -> CELAR EVENT STACK -> READ NV -> SENSE ON */
	ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_SENSE_OFF, NULL, 0);
	if (ret < 0) {
		input_err(true, &ts->client->dev, "%s: fail to write Sense_off\n", __func__);
		goto out_nvm;
	}

	input_dbg(false, &ts->client->dev, "%s: SENSE OFF\n", __func__);

	sec_ts_delay(100);

	ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_CLEAR_EVENT_STACK, NULL, 0);
	if (ret < 0) {
		input_err(true, &ts->client->dev, "%s: i2c write clear event failed\n", __func__);
		goto out_nvm;
	}

	input_dbg(false, &ts->client->dev, "%s: CLEAR EVENT STACK\n", __func__);

	sec_ts_delay(100);

	sec_ts_locked_release_all_finger(ts);

	/* send NV data using command
	 * Use TSP NV area : in this model, use only one byte
	 * buff[0] : offset from user NVM storage
	 * buff[1] : length of stroed data - 1 (ex. using 1byte, value is  1 - 1 = 0)
	 */
	memset(buff, 0x00, 2);
	buff[0] = offset;
	ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_NVM, buff, 2);
	if (ret < 0) {
		input_err(true, &ts->client->dev, "%s: nvm send command failed. ret: %d\n", __func__, ret);
		goto out_nvm;
	}

	sec_ts_delay(20);

	/* read NV data
	 * Use TSP NV area : in this model, use only one byte
	 */
	ret = ts->sec_ts_i2c_read(ts, SEC_TS_CMD_NVM, buff, 1);
	if (ret < 0) {
		input_err(true, &ts->client->dev, "%s: nvm send command failed. ret: %d\n", __func__, ret);
		goto out_nvm;
	}

	input_info(true, &ts->client->dev, "%s: offset:%u  data:%02X\n", __func__,offset, buff[0]);

out_nvm:
	ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_SENSE_ON, NULL, 0);
	if (ret < 0)
		input_err(true, &ts->client->dev, "%s: fail to write Sense_on\n", __func__);

	input_dbg(false, &ts->client->dev, "%s: SENSE ON\n", __func__);

	return buff[0];
}

#ifdef MINORITY_REPORT

/*	ts->defect_probability is FFFFF
 *
 *	0	is 100% normal.
 *	1~9	is normal, but need check
 *	A~E	is abnormal, must check
 *	F	is Device defect
 *
 *	F----	: ito
 *	-F---	: rawdata
 *	--A--	: crc
 *	---A-	: i2c_err
 *	----A	: wet
 */
void minority_report_calculate_rawdata(struct sec_ts_data *ts)
{
	int ii;
	int temp = 0;
	int max = -30000;
	int min = 30000;
	int node_gap = 1;

	if (!ts->tx_count) {
		ts->item_rawdata = 0xD;
		return;
	}

	for (ii = 0; ii < (ts->rx_count * ts->tx_count); ii++) {
		if (max < ts->pFrame[ii]) {
			ts->max_ambient = max = ts->pFrame[ii];
			ts->max_ambient_channel_tx = ii % ts->tx_count;
			ts->max_ambient_channel_rx = ii / ts->tx_count;
		}
		if (min > ts->pFrame[ii]) {
			ts->min_ambient = min = ts->pFrame[ii];
			ts->min_ambient_channel_tx = ii % ts->tx_count;
			ts->min_ambient_channel_rx = ii / ts->tx_count;
		}

		if ((ii + 1) % (ts->tx_count) != 0) {
			temp = ts->pFrame[ii] - ts->pFrame[ii+1];
			if (temp < 0)
				temp = -temp;
			if (temp > node_gap)
				node_gap = temp;
		}

		if (ii < (ts->rx_count - 1) * ts->tx_count) {
			temp = ts->pFrame[ii] - ts->pFrame[ii + ts->tx_count];
			if (temp < 0)
				temp = -temp;
			if (temp > node_gap)
				node_gap = temp;
		}
	}

	if (max >= 80 || min <= -80)
		ts->item_rawdata = 0xF;
	else if ((max >= 50 || min <= -50) && (node_gap > 40))
		ts->item_rawdata = 0xC;
	else if (max >= 50 || min <= -50)
		ts->item_rawdata = 0xB;
	else if (node_gap > 40)
		ts->item_rawdata = 0xA;
	else if ((max >= 40 || min <= -40) && (node_gap > 30))
		ts->item_rawdata = 0x3;
	else if (max >= 40 || min <= -40)
		ts->item_rawdata = 0x2;
	else if (node_gap > 30)
		ts->item_rawdata = 0x1;
	else
		ts->item_rawdata = 0;

	input_info(true, &ts->client->dev, "%s min:%d,max:%d,node gap:%d =>%X\n",
			__func__, min, max, node_gap, ts->item_rawdata);

}

void minority_report_calculate_ito(struct sec_ts_data *ts)
{

	if (ts->ito_test[0] ||  ts->ito_test[1] || ts->ito_test[2] || ts->ito_test[3])
		ts->item_ito = 0xF;
	else
		ts->item_ito = 0;
}

u8 minority_report_check_count(int value)
{
	u8 ret;

	if (value > 160)
		ret = 0xA;
	else if (value > 90)
		ret = 3;
	else if (value > 40)
		ret = 2;
	else if (value > 10)
		ret = 1;
	else
		ret = 0;

	return ret;
}

void minority_report_sync_latest_value(struct sec_ts_data *ts)
{
	u32 temp = 0;

	/* crc */
	if (ts->checksum_result == 1)
		ts->item_crc = 0xA;

	/* i2c_err */
	ts->item_i2c_err = minority_report_check_count(ts->comm_err_count);

	/* wet */
	ts->item_wet = minority_report_check_count(ts->wet_count);

	temp |= (ts->item_ito & 0xF) << 16;
	temp |= (ts->item_rawdata & 0xF) << 12;
	temp |= (ts->item_crc & 0xF) << 8;
	temp |= (ts->item_i2c_err & 0xF) << 4;
	temp |= (ts->item_wet & 0xF);

	ts->defect_probability = temp;
}
#endif

static void sec_ts_swap(u8 *a, u8 *b)
{
	u8 temp = *a;

	*a = *b;
	*b = temp;
}

static void rearrange_sft_result(u8 *data, int length)
{
	int i;

	for(i = 0; i < length; i += 4) {
		sec_ts_swap(&data[i], &data[i + 3]);
		sec_ts_swap(&data[i + 1], &data[i + 2]);
	}
}

static int execute_selftest(struct sec_ts_data *ts, bool save_result)
{
	int rc;
	u8 tpara[2] = {0x23, 0x40};
	u8 *rBuff;
	int i;
	int result_size = SEC_TS_SELFTEST_REPORT_SIZE + ts->tx_count * ts->rx_count * 2;

	/* save selftest result in flash */
	if (save_result)
		tpara[0] = 0x23;
	else
		tpara[0] = 0xA3;

	rBuff = kzalloc(result_size, GFP_KERNEL);
	if (!rBuff)
		return -ENOMEM;

	input_info(true, &ts->client->dev, "%s: Self test start!\n", __func__);
	rc = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_SELFTEST, tpara, 2);
	if (rc < 0) {
		input_err(true, &ts->client->dev, "%s: Send selftest cmd failed!\n", __func__);
		goto err_exit;
	}

	sec_ts_delay(350);

	rc = sec_ts_wait_for_ready(ts, SEC_TS_VENDOR_ACK_SELF_TEST_DONE);
	if (rc < 0) {
		input_err(true, &ts->client->dev, "%s: Selftest execution time out!\n", __func__);
		goto err_exit;
	}

	input_info(true, &ts->client->dev, "%s: Self test done!\n", __func__);

	rc = ts->sec_ts_i2c_read(ts, SEC_TS_READ_SELFTEST_RESULT, rBuff, result_size);
	if (rc < 0) {
		input_err(true, &ts->client->dev, "%s: Selftest execution time out!\n", __func__);
		goto err_exit;
	}
	rearrange_sft_result(rBuff, result_size);

	for (i = 0; i < 80; i += 4) {
		if (i % 8 == 0) pr_cont("\n");
		if (i % 4 == 0) pr_cont("%s sec_ts : ", SECLOG);

		if (i / 4 == 0) pr_cont("SIG");
		else if (i / 4 == 1) pr_cont("VER");
		else if (i / 4 == 2) pr_cont("SIZ");
		else if (i / 4 == 3) pr_cont("CRC");
		else if (i / 4 == 4) pr_cont("RES");
		else if (i / 4 == 5) pr_cont("COU");
		else if (i / 4 == 6) pr_cont("PAS");
		else if (i / 4 == 7) pr_cont("FAI");
		else if (i / 4 == 8) pr_cont("CHA");
		else if (i / 4 == 9) pr_cont("AMB");
		else if (i / 4 == 10) pr_cont("RXS");
		else if (i / 4 == 11) pr_cont("TXS");
		else if (i / 4 == 12) pr_cont("RXO");
		else if (i / 4 == 13) pr_cont("TXO");
		else if (i / 4 == 14) pr_cont("RXG");
		else if (i / 4 == 15) pr_cont("TXG");
		else if (i / 4 == 16) pr_cont("RXR");
		else if (i / 4 == 17) pr_cont("TXT");
		else if (i / 4 == 18) pr_cont("RXT");
		else if (i / 4 == 19) pr_cont("TXR");

		pr_cont(" %2X, %2X, %2X, %2X  ", rBuff[i], rBuff[i + 1], rBuff[i + 2], rBuff[i + 3]);

		if (i / 4 == 4) {
			if ((rBuff[i + 3] & 0x30) != 0)// RX, RX open check.
				rc = 0;
			else
				rc = 1;

			ts->ito_test[0] = rBuff[i];
			ts->ito_test[1] = rBuff[i + 1];
			ts->ito_test[2] = rBuff[i + 2];
			ts->ito_test[3] = rBuff[i + 3];
		}
	}

err_exit:
	kfree(rBuff);
	return rc;
}