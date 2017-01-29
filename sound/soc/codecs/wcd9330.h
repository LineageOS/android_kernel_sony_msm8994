/* Copyright (c) 2012-2015, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
/*
 * NOTE: This file has been modified by Sony Mobile Communications Inc.
 * Modifications are Copyright (c) 2014 Sony Mobile Communications Inc,
 * and licensed under the license of the file.
 */
#ifndef WCD9330_H
#define WCD9330_H

#include <sound/soc.h>
#include <sound/jack.h>
#include <sound/apr_audio-v2.h>
#include <linux/mfd/wcd9xxx/wcd9xxx-slimslave.h>
#include "wcd9xxx-mbhc.h"
#include "wcd9xxx-resmgr.h"
#include "wcd9xxx-common.h"

#define TOMTOM_NUM_REGISTERS 0x400
#define TOMTOM_MAX_REGISTER (TOMTOM_NUM_REGISTERS-1)
#define TOMTOM_CACHE_SIZE TOMTOM_NUM_REGISTERS

#define TOMTOM_REG_VAL(reg, val)		{reg, 0, val}
#define TOMTOM_MCLK_ID 0

#define TOMTOM_REGISTER_START_OFFSET 0x800
#define TOMTOM_SB_PGD_PORT_RX_BASE   0x40
#define TOMTOM_SB_PGD_PORT_TX_BASE   0x50

#define WCD9330_DMIC_CLK_DIV_2 0x00
#define WCD9330_DMIC_CLK_DIV_3 0x01
#define WCD9330_DMIC_CLK_DIV_4 0x02
#define WCD9330_DMIC_CLK_DIV_6 0x03
#define WCD9330_DMIC_CLK_DIV_16 0x04

#define WCD9330_HDRIVE_DMIC_CLK_I_2MA 0x0
#define WCD9330_HDRIVE_DMIC_CLK_I_4MA 0x1
#define WCD9330_HDRIVE_DMIC_CLK_I_6MA 0x2
#define WCD9330_HDRIVE_DMIC_CLK_I_8MA 0x3
#define WCD9330_HDRIVE_DMIC_CLK_I_10MA 0x4
#define WCD9330_HDRIVE_DMIC_CLK_I_12MA 0x5
#define WCD9330_HDRIVE_DMIC_CLK_I_14MA 0x6
#define WCD9330_HDRIVE_DMIC_CLK_I_16MA 0x7

#define TOMTOM_ZDET_SUPPORTED true

#define WCD9330_SPKDRV_OCP_CURR_LIMIT_I_0P0_A	0x0
#define WCD9330_SPKDRV_OCP_CURR_LIMIT_I_0P375_A 0x1
#define WCD9330_SPKDRV_OCP_CURR_LIMIT_I_0P750_A 0x2
#define WCD9330_SPKDRV_OCP_CURR_LIMIT_I_1P125_A 0x3
#define WCD9330_SPKDRV_OCP_CURR_LIMIT_I_1P500_A 0x4
#define WCD9330_SPKDRV_OCP_CURR_LIMIT_I_1P875_A 0x5
#define WCD9330_SPKDRV_OCP_CURR_LIMIT_I_2P250_A 0x6
#define WCD9330_SPKDRV_OCP_CURR_LIMIT_I_2P625_A 0x7
#define WCD9330_SPKDRV_OCP_CURR_LIMIT_I_3P000_A 0x8
#define WCD9330_SPKDRV_OCP_CURR_LIMIT_I_3P375_A 0x9
#define WCD9330_SPKDRV_OCP_CURR_LIMIT_I_3P750_A 0xA
#define WCD9330_SPKDRV_OCP_CURR_LIMIT_I_4P125_A 0xB
#define WCD9330_SPKDRV_OCP_CURR_LIMIT_I_4P500_A 0xC
#define WCD9330_SPKDRV_OCP_CURR_LIMIT_I_4P875_A 0xD
#define WCD9330_SPKDRV_OCP_CURR_LIMIT_I_5P250_A 0xE
#define WCD9330_SPKDRV_OCP_CURR_LIMIT_I_5P625_A 0xF

extern const u8 tomtom_reg_readable[TOMTOM_CACHE_SIZE];
extern const u8 tomtom_reset_reg_defaults[TOMTOM_CACHE_SIZE];
struct tomtom_codec_dai_data {
	u32 rate;
	u32 *ch_num;
	u32 ch_act;
	u32 ch_tot;
};

enum tomtom_pid_current {
	TOMTOM_PID_MIC_2P5_UA,
	TOMTOM_PID_MIC_5_UA,
	TOMTOM_PID_MIC_10_UA,
	TOMTOM_PID_MIC_20_UA,
};

enum tomtom_mbhc_analog_pwr_cfg {
	TOMTOM_ANALOG_PWR_COLLAPSED = 0,
	TOMTOM_ANALOG_PWR_ON,
	TOMTOM_NUM_ANALOG_PWR_CONFIGS,
};

enum {
	HPH_PA_NONE = 0,
	HPH_PA_R,
	HPH_PA_L,
	HPH_PA_L_R,
};

/* Number of input and output Slimbus port */
enum {
	TOMTOM_RX1 = 0,
	TOMTOM_RX2,
	TOMTOM_RX3,
	TOMTOM_RX4,
	TOMTOM_RX5,
	TOMTOM_RX6,
	TOMTOM_RX7,
	TOMTOM_RX8,
	TOMTOM_RX9,
	TOMTOM_RX10,
	TOMTOM_RX11,
	TOMTOM_RX12,
	TOMTOM_RX13,
	TOMTOM_RX_MAX,
};

enum {
	TOMTOM_TX1 = 0,
	TOMTOM_TX2,
	TOMTOM_TX3,
	TOMTOM_TX4,
	TOMTOM_TX5,
	TOMTOM_TX6,
	TOMTOM_TX7,
	TOMTOM_TX8,
	TOMTOM_TX9,
	TOMTOM_TX10,
	TOMTOM_TX11,
	TOMTOM_TX12,
	TOMTOM_TX13,
	TOMTOM_TX14,
	TOMTOM_TX15,
	TOMTOM_TX16,
	TOMTOM_TX_MAX,
};

extern int tomtom_mclk_enable(struct snd_soc_codec *codec, int mclk_enable,
			     bool bg_clk_locked);
extern int tomtom_hs_detect(struct snd_soc_codec *codec,
			   struct wcd9xxx_mbhc_config *mbhc_cfg);
extern void tomtom_hs_detect_exit(struct snd_soc_codec *codec);
extern void *tomtom_get_afe_config(struct snd_soc_codec *codec,
				  enum afe_config_type config_type);

extern void tomtom_event_register(
	int (*machine_event_cb)(struct snd_soc_codec *codec,
				enum wcd9xxx_codec_event),
	struct snd_soc_codec *codec);
extern void tomtom_register_ext_clk_cb(
	int (*codec_ext_clk_en)(struct snd_soc_codec *codec,
				int enable, bool bg_clk_locked),
	int (*get_ext_clk_cnt) (void),
	struct snd_soc_codec *codec);
extern int tomtom_enable_qfuse_sensing(struct snd_soc_codec *codec);
extern void tomtom_codec_bg_clk_lock_cntl(struct snd_soc_codec *codec,
	bool acquire);
#endif
