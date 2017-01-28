/*
 * Copyright (c) 2013-2015, Linux Foundation. All rights reserved.
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
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/miscdevice.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/time.h>
#include <linux/atomic.h>
#include <sound/apr_audio-v2.h>
#include <sound/lsm_params.h>
#include <sound/q6core.h>
#include <sound/q6lsm.h>
#include <asm/ioctls.h>
#include <linux/memory.h>
#include <linux/msm_audio_ion.h>
#include <sound/q6afe-v2.h>
#include <sound/audio_cal_utils.h>

#define APR_TIMEOUT	(5 * HZ)
#define LSM_ALIGN_BOUNDARY 512
#define LSM_SAMPLE_RATE 16000
#define QLSM_PARAM_ID_MINOR_VERSION 1
static int lsm_afe_port;

enum {
	CMD_STATE_CLEARED = 0,
	CMD_STATE_WAIT_RESP = 1,
};

enum {
	LSM_INVALID_SESSION_ID = 0,
	LSM_MIN_SESSION_ID = 1,
	LSM_MAX_SESSION_ID = 8,
	LSM_CONTROL_SESSION = 0x0F,
};

#define CHECK_SESSION(x) (x < LSM_MIN_SESSION_ID || x > LSM_MAX_SESSION_ID)
struct lsm_common {
	void *apr;
	atomic_t apr_users;
	struct lsm_client	common_client[LSM_MAX_SESSION_ID + 1];
	struct cal_type_data *cal_data;
	struct mutex apr_lock;
};

static struct lsm_common lsm_common;
/*
 * mmap_handle_p can point either client->sound_model.mem_map_handle or
 * lsm_common.mmap_handle_for_cal.
 * mmap_lock must be held while accessing this.
 */
static spinlock_t mmap_lock;
static uint32_t *mmap_handle_p;

static spinlock_t lsm_session_lock;
static struct lsm_client *lsm_session[LSM_MAX_SESSION_ID + 1];

static int q6lsm_mmapcallback(struct apr_client_data *data, void *priv);
static int q6lsm_send_cal(struct lsm_client *client);

static int q6lsm_callback(struct apr_client_data *data, void *priv)
{
	struct lsm_client *client = (struct lsm_client *)priv;
	uint32_t token;
	uint32_t *payload;

	if (!client || !data) {
		pr_err("%s: client %p data %p\n",
			__func__, client, data);
		WARN_ON(1);
		return -EINVAL;
	}

	if (data->opcode == RESET_EVENTS) {
		pr_debug("%s: SSR event received 0x%x, event 0x%x, proc 0x%x\n",
			 __func__, data->opcode, data->reset_event,
			 data->reset_proc);
		return 0;
	}

	payload = data->payload;
	pr_debug("%s: Session %d opcode 0x%x token 0x%x payload size %d\n"
			 "payload [0] = 0x%x\n", __func__, client->session,
		data->opcode, data->token, data->payload_size, payload[0]);
	if (data->opcode == LSM_DATA_EVENT_READ_DONE) {
		struct lsm_cmd_read_done read_done;
		token = data->token;
		if (data->payload_size > sizeof(read_done)) {
			pr_err("%s: read done error payload size %d expected size %zd\n",
				__func__, data->payload_size,
				sizeof(read_done));
			return -EINVAL;
		}
		pr_debug("%s: opcode %x status %x lsw %x msw %x mem_map handle %x\n",
			__func__, data->opcode, payload[0], payload[1],
			payload[2], payload[3]);
		read_done.status = payload[0];
		read_done.buf_addr_lsw = payload[1];
		read_done.buf_addr_msw = payload[2];
		read_done.mem_map_handle = payload[3];
		read_done.total_size = payload[4];
		read_done.offset = payload[5];
		if (client->cb)
			client->cb(data->opcode, data->token,
					(void *)&read_done,
					client->priv);
		return 0;
	} else if (data->opcode == APR_BASIC_RSP_RESULT) {
		token = data->token;
		switch (payload[0]) {
		case LSM_SESSION_CMD_START:
		case LSM_SESSION_CMD_STOP:
		case LSM_SESSION_CMD_SET_PARAMS:
		case LSM_SESSION_CMD_OPEN_TX:
		case LSM_SESSION_CMD_CLOSE_TX:
		case LSM_SESSION_CMD_REGISTER_SOUND_MODEL:
		case LSM_SESSION_CMD_DEREGISTER_SOUND_MODEL:
		case LSM_SESSION_CMD_SHARED_MEM_UNMAP_REGIONS:
		case LSM_SESSION_CMD_EOB:
		case LSM_SESSION_CMD_READ:
			if (token != client->session &&
			    payload[0] !=
				LSM_SESSION_CMD_DEREGISTER_SOUND_MODEL) {
				pr_err("%s: Invalid session %d receivced expected %d\n",
					__func__, token, client->session);
				return -EINVAL;
			}
			if (payload[1] != 0)
				pr_err("%s: cmd %d failed status %d\n",
				__func__, payload[0], payload[1]);
			if (atomic_cmpxchg(&client->cmd_state,
					   CMD_STATE_WAIT_RESP,
					   CMD_STATE_CLEARED) ==
					       CMD_STATE_WAIT_RESP)
				wake_up(&client->cmd_wait);
			break;
		default:
			pr_debug("%s: Unknown command 0x%x\n",
				__func__, payload[0]);
			break;
		}
		return 0;
	}

	if (client->cb)
		client->cb(data->opcode, data->token, data->payload,
			   client->priv);

	return 0;
}

static int q6lsm_session_alloc(struct lsm_client *client)
{
	unsigned long flags;
	int n, ret = -ENOMEM;

	spin_lock_irqsave(&lsm_session_lock, flags);
	for (n = LSM_MIN_SESSION_ID; n <= LSM_MAX_SESSION_ID; n++) {
		if (!lsm_session[n]) {
			lsm_session[n] = client;
			ret = n;
			break;
		}
	}
	spin_unlock_irqrestore(&lsm_session_lock, flags);
	pr_debug("%s: Alloc Session %d", __func__, n);
	return ret;
}

static void q6lsm_session_free(struct lsm_client *client)
{
	unsigned long flags;
	pr_debug("%s: Freeing session ID %d\n", __func__, client->session);
	spin_lock_irqsave(&lsm_session_lock, flags);
	lsm_session[client->session] = LSM_INVALID_SESSION_ID;
	spin_unlock_irqrestore(&lsm_session_lock, flags);
	client->session = LSM_INVALID_SESSION_ID;
}

static void *q6lsm_mmap_apr_reg(void)
{
	if (atomic_inc_return(&lsm_common.apr_users) == 1) {
		lsm_common.apr =
		    apr_register("ADSP", "LSM", q6lsm_mmapcallback,
				 0x0FFFFFFFF, &lsm_common);
		if (!lsm_common.apr) {
			pr_debug("%s: Unable to register APR LSM common port\n",
				 __func__);
			atomic_dec(&lsm_common.apr_users);
		}
	}
	return lsm_common.apr;
}

static int q6lsm_mmap_apr_dereg(void)
{
	if (atomic_read(&lsm_common.apr_users) <= 0) {
		WARN("%s: APR common port already closed\n", __func__);
	} else {
		if (atomic_dec_return(&lsm_common.apr_users) == 0) {
			apr_deregister(lsm_common.apr);
			pr_debug("%s: APR De-Register common port\n", __func__);
		}
	}
	return 0;
}

struct lsm_client *q6lsm_client_alloc(lsm_app_cb cb, void *priv)
{
	struct lsm_client *client;
	int n;

	client = kzalloc(sizeof(struct lsm_client), GFP_KERNEL);
	if (!client)
		return NULL;
	n = q6lsm_session_alloc(client);
	if (n <= 0) {
		kfree(client);
		return NULL;
	}
	client->session = n;
	client->cb = cb;
	client->priv = priv;
	if (CHECK_SESSION(client->session)) {
		pr_err("%s: Client session %d\n",
			__func__, client->session);
		kfree(client);
		return NULL;
	}
	pr_debug("%s: Client Session %d\n", __func__, client->session);
	client->apr = apr_register("ADSP", "LSM", q6lsm_callback,
				   ((client->session) << 8 | client->session),
				   client);

	if (client->apr == NULL) {
		pr_err("%s: Registration with APR failed\n", __func__);
		goto fail;
	}

	pr_debug("%s: Registering the common port with APR\n", __func__);
	client->mmap_apr = q6lsm_mmap_apr_reg();
	if (!client->mmap_apr) {
		pr_err("%s: APR registration failed\n", __func__);
		goto fail;
	}

	init_waitqueue_head(&client->cmd_wait);
	mutex_init(&client->cmd_lock);
	atomic_set(&client->cmd_state, CMD_STATE_CLEARED);
	pr_debug("%s: New client allocated\n", __func__);
	return client;
fail:
	q6lsm_client_free(client);
	return NULL;
}

void q6lsm_client_free(struct lsm_client *client)
{
	if (!client)
		return;
	if (CHECK_SESSION(client->session)) {
		pr_err("%s: Invalid Session %d\n", __func__, client->session);
		return;
	}
	apr_deregister(client->apr);
	client->mmap_apr = NULL;
	q6lsm_session_free(client);
	q6lsm_mmap_apr_dereg();
	mutex_destroy(&client->cmd_lock);
	kfree(client);
	client = NULL;
}

/*
 * q6lsm_apr_send_pkt : If wait == true, hold mutex to prevent from preempting
 *			other thread's wait.
 *			If mmap_handle_p != NULL, disable irq and spin lock to
 *			protect mmap_handle_p
 */
static int q6lsm_apr_send_pkt(struct lsm_client *client, void *handle,
			      void *data, bool wait, uint32_t *mmap_p)
{
	int ret;
	unsigned long flags = 0;

	pr_debug("%s: enter wait %d\n", __func__, wait);
	if (wait)
		mutex_lock(&lsm_common.apr_lock);
	if (mmap_p) {
		WARN_ON(!wait);
		spin_lock_irqsave(&mmap_lock, flags);
		mmap_handle_p = mmap_p;
	}
	atomic_set(&client->cmd_state, CMD_STATE_WAIT_RESP);
	ret = apr_send_pkt(handle, data);
	if (mmap_p)
		spin_unlock_irqrestore(&mmap_lock, flags);

	if (ret < 0) {
		pr_err("%s: apr_send_pkt failed %d\n", __func__, ret);
	} else if (wait) {
		ret = wait_event_timeout(client->cmd_wait,
					 (atomic_read(&client->cmd_state) ==
					      CMD_STATE_CLEARED),
					 APR_TIMEOUT);
		if (likely(ret))
			ret = 0;
		else
			pr_err("%s: wait timedout\n", __func__);
	} else {
		ret = 0;
	}
	if (wait)
		mutex_unlock(&lsm_common.apr_lock);

	pr_debug("%s: leave ret %d\n", __func__, ret);
	return ret;
}

static void q6lsm_add_hdr(struct lsm_client *client, struct apr_hdr *hdr,
			uint32_t pkt_size, bool cmd_flg)
{
	pr_debug("%s: pkt_size %d cmd_flg %d session %d\n", __func__,
		pkt_size, cmd_flg, client->session);
	hdr->hdr_field = APR_HDR_FIELD(APR_MSG_TYPE_SEQ_CMD,
				       APR_HDR_LEN(sizeof(struct apr_hdr)),
				       APR_PKT_VER);
	hdr->src_svc = APR_SVC_LSM;
	hdr->src_domain = APR_DOMAIN_APPS;
	hdr->dest_svc = APR_SVC_LSM;
	hdr->dest_domain = APR_DOMAIN_ADSP;
	hdr->src_port = ((client->session << 8) & 0xFF00) | client->session;
	hdr->dest_port = ((client->session << 8) & 0xFF00) | client->session;
	hdr->pkt_size = pkt_size;
	if (cmd_flg)
		hdr->token = client->session;
}

int q6lsm_open(struct lsm_client *client, uint16_t app_id)
{
	int rc = 0;
	struct lsm_stream_cmd_open_tx open;

	memset(&open, 0, sizeof(open));
	q6lsm_add_hdr(client, &open.hdr, sizeof(open), true);
	switch (client->app_id) {
	case LSM_VOICE_WAKEUP_APP_ID:
	case LSM_VOICE_WAKEUP_APP_ID_V2:
		open.app_id = client->app_id;
		break;
	default:
		pr_err("%s:  default err 0x%x\n", __func__, client->app_id);
		rc = -EINVAL;
		break;
	}
	if (!rc) {
		open.sampling_rate = LSM_SAMPLE_RATE;
		open.hdr.opcode = LSM_SESSION_CMD_OPEN_TX;
		rc = q6lsm_apr_send_pkt(client, client->apr,
					&open, true, NULL);
		if (rc)
			pr_err("%s: Open failed opcode 0x%x, rc %d\n",
			       __func__, open.hdr.opcode, rc);
	}
	pr_debug("%s: leave %d\n", __func__, rc);
	return rc;
}

static int q6lsm_set_operation_mode(
			struct lsm_param_op_mode *op_mode,
			uint16_t mode)
{
	if (op_mode == NULL)
		return -EINVAL;
	op_mode->common.module_id  = LSM_MODULE_ID_VOICE_WAKEUP;
	op_mode->common.param_id = LSM_PARAM_ID_OPERATION_MODE;
	op_mode->common.param_size =
	    sizeof(struct lsm_param_op_mode) - sizeof(op_mode->common);
	op_mode->common.reserved = 0;
	op_mode->minor_version = QLSM_PARAM_ID_MINOR_VERSION;
	op_mode->mode = mode;
	op_mode->reserved = 0;
	pr_debug("%s: mode = 0x%x", __func__, mode);
	return 0;
}
static int q6lsm_set_port_connected(
			struct lsm_param_connect_to_port *connect_to_port,
			uint16_t connected_port)
{
	if (connect_to_port == NULL) {
		pr_err("%s: err with connect_to_port\n", __func__);
		return -EINVAL;
	}
	connect_to_port->common.module_id = LSM_MODULE_ID_VOICE_WAKEUP;
	connect_to_port->common.param_id = LSM_PARAM_ID_CONNECT_TO_PORT;
	connect_to_port->common.param_size =
				(sizeof(struct lsm_param_connect_to_port)
					- sizeof(connect_to_port->common));
	connect_to_port->common.reserved = 0;
	connect_to_port->minor_version = QLSM_PARAM_ID_MINOR_VERSION;
	connect_to_port->port_id = connected_port;
	connect_to_port->reserved = 0;
	pr_debug("%s: port= %d", __func__, connected_port);
	return 0;
}

static int q6lsm_set_kw_sensitivity(
			struct lsm_param_kw_detect_sensitivity *kwds,
			uint16_t kw_sensitivity)
{
	if (kwds == NULL) {
		pr_err("%s: err with kwds\n", __func__);
		return -EINVAL;
	}
	kwds->common.module_id = LSM_MODULE_ID_VOICE_WAKEUP;
	kwds->common.param_id = LSM_PARAM_ID_KEYWORD_DETECT_SENSITIVITY;
	kwds->common.param_size =
			(sizeof(struct lsm_param_kw_detect_sensitivity)
				- sizeof(kwds->common));
	kwds->common.reserved = 0;
	kwds->minor_version = QLSM_PARAM_ID_MINOR_VERSION;
	kwds->keyword_sensitivity = kw_sensitivity;
	pr_debug("%s: KW = %d\n", __func__, kw_sensitivity);
	kwds->reserved = 0;
	return 0;
}

static int q6lsm_set_user_sensitivity(
			struct lsm_param_user_detect_sensitivity *uds,
			uint16_t user_sensitivity)
{
	if (uds == NULL) {
		pr_err("%s: err with uds\n", __func__);
		return -EINVAL;
	}
	uds->common.module_id = LSM_MODULE_ID_VOICE_WAKEUP;
	uds->common.param_id = LSM_PARAM_ID_USER_DETECT_SENSITIVITY;
	uds->common.param_size =
			(sizeof(struct lsm_param_user_detect_sensitivity)
				-sizeof(uds->common));
	uds->common.reserved = 0;
	uds->minor_version = QLSM_PARAM_ID_MINOR_VERSION;
	uds->user_sensitivity = user_sensitivity;
	pr_debug("%s: US = %d", __func__, user_sensitivity);
	uds->reserved = 0;
	return 0;
}

static int q6lsm_set_confidence_level(
			struct lsm_param_min_confidence_levels *cfl,
			uint8_t num_confidence_level,
			uint8_t *confidence_level)
{

	uint8_t i = 0;
	uint8_t padd_size = 0;

	if (cfl == NULL) {
		pr_err("%s: err with cfl\n", __func__);
		return -EINVAL;
	}
	padd_size = (4 - (num_confidence_level % 4)) - 1;
	cfl->common.module_id = LSM_MODULE_ID_VOICE_WAKEUP;
	cfl->common.param_id = LSM_PARAM_ID_MIN_CONFIDENCE_LEVELS;
	cfl->common.param_size = ((sizeof(uint8_t) + num_confidence_level
				  + padd_size)) * sizeof(uint8_t);
	cfl->num_confidence_levels = num_confidence_level;
	pr_debug("%s: CMD PARAM SIZE = %d\n", __func__, cfl->common.param_size);
	memset(&cfl->confidence_level[0], 0,
	       sizeof(uint8_t) * MAX_NUM_CONFIDENCE);
	memcpy(&cfl->confidence_level[0], confidence_level,
	       num_confidence_level);
	pr_debug("%s: Num conf_level = %d\n", __func__, num_confidence_level);
	for (i = 0; i < num_confidence_level; i++)
		pr_debug("%s: Confi value = %d\n", __func__,
			 cfl->confidence_level[i]);
	return 0;
}

static int q6lsm_set_params(struct lsm_client *client)
{
	int rc;
	struct lsm_cmd_set_params params;
	struct lsm_cmd_set_params_conf_v2 params_conf_v2;
	struct lsm_cmd_set_params_v2 params_v2;
	struct apr_hdr  *hdr;
	uint32_t hdr_size;
	struct lsm_param_connect_to_port *connect_to_port;
	struct lsm_param_op_mode *op_mode;
	struct lsm_param_kw_detect_sensitivity *kwds;
	struct lsm_param_user_detect_sensitivity *uds;
	struct lsm_param_min_confidence_levels *cfl;
	void *param_data;

	pr_debug("%s: Set KW/Confidence params\n", __func__);
	if (client->snd_model_ver_inuse == SND_MODEL_IN_USE_V1) {
		q6lsm_add_hdr(client, &params.hdr, sizeof(params), true);
		hdr = &params.hdr;
		hdr_size = sizeof(params);
		params.hdr.opcode = LSM_SESSION_CMD_SET_PARAMS;
		params.data_payload_addr_lsw = 0;
		params.data_payload_addr_msw = 0;
		params.mem_map_handle = 0;
		params.data_payload_size =
			sizeof(struct lsm_params_payload);
		connect_to_port = &params.payload.connect_to_port;
		op_mode = &params.payload.op_mode;
		kwds = &params.payload.kwds;
		uds = &params.payload.uds;
		param_data = &params;
	} else if (client->snd_model_ver_inuse == SND_MODEL_IN_USE_V2) {
		q6lsm_add_hdr(client, &params_v2.hdr, sizeof(params_v2), true);
		hdr = &params_v2.hdr;
		hdr_size = sizeof(params_v2);
		params_v2.hdr.opcode = LSM_SESSION_CMD_SET_PARAMS;
		params_v2.data_payload_addr_lsw = 0;
		params_v2.data_payload_addr_msw = 0;
		params_v2.mem_map_handle = 0;
		params_v2.data_payload_size =
			sizeof(struct lsm_params_payload_v2);
		connect_to_port = &params_v2.payload.connect_to_port;
		op_mode = &params_v2.payload.op_mode;
		param_data = &params_v2;
	} else {
		pr_err("%s: Invalid sound model %d\n", __func__,
		       client->snd_model_ver_inuse);
		rc = -EINVAL;
		return rc;
	}

	rc = q6lsm_set_operation_mode(op_mode, client->mode);
	if (rc) {
		pr_err("%s: err operation rc %d\n", __func__, rc);
		goto exit;
	}
	rc = q6lsm_set_port_connected(connect_to_port,
				      client->connect_to_port);
	if (rc) {
		pr_err("%s: err port rc %d\n", __func__, rc);
		goto exit;
	}

	if (client->snd_model_ver_inuse == SND_MODEL_IN_USE_V1) {
		rc = q6lsm_set_kw_sensitivity(kwds,
					      client->kw_sensitivity);
		if (rc) {
			pr_err("%s: err set_kw rc %d\n", __func__, rc);
			goto exit;
		}
		rc = q6lsm_set_user_sensitivity(uds,
						client->user_sensitivity);
		if (rc) {
			pr_err("%s: err set user rc %d\n", __func__, rc);
			goto exit;
		}
	}

	rc = q6lsm_apr_send_pkt(client, client->apr, param_data, true, NULL);
	if (rc)
		pr_err("%s: Failed set_params opcode 0x%x, rc %d\n",
		       __func__, hdr->opcode, rc);

	if (client->snd_model_ver_inuse == SND_MODEL_IN_USE_V2) {
		q6lsm_add_hdr(client, &params_conf_v2.hdr,
			      sizeof(params_conf_v2), true);
		hdr = &params_conf_v2.hdr;
		hdr_size = sizeof(params_conf_v2);
		params_conf_v2.hdr.opcode = LSM_SESSION_CMD_SET_PARAMS;
		params_conf_v2.data_payload_addr_lsw = 0;
		params_conf_v2.data_payload_addr_msw = 0;
		params_conf_v2.mem_map_handle = 0;
		params_conf_v2.data_payload_size =
			sizeof(struct lsm_param_min_confidence_levels);
		param_data = &params_conf_v2;
		cfl = &params_conf_v2.conf_payload;
		rc = q6lsm_set_confidence_level(cfl,
					client->num_confidence_levels,
					client->confidence_levels);
		if (rc) {
			pr_err("%s: err confidence rc %d\n", __func__, rc);
			goto exit;
		}
		rc = q6lsm_apr_send_pkt(client, client->apr,
					param_data, true, NULL);
		if (rc) {
			pr_err("%s: err packet rc %d\n", __func__, rc);
			goto exit;
		}
	}

	pr_debug("%s: leave %d\n", __func__, rc);
exit:
	return rc;
}

int q6lsm_set_kw_sensitivity_level(struct lsm_client *client,
				   u16 minkeyword, u16 minuser)
{
	int rc = 0;
	if (client->snd_model_ver_inuse != SND_MODEL_IN_USE_V1) {
		pr_err("%s: Invalid snd model version\n",
			   __func__);
		rc = -EINVAL;
		goto exit;
	}
	client->kw_sensitivity = minkeyword;
	client->user_sensitivity = minuser;
exit:
	return rc;
}

void set_lsm_port(int lsm_port)
{
	lsm_afe_port = lsm_port;
}

int get_lsm_port()
{
	return lsm_afe_port;
}

int q6lsm_set_data(struct lsm_client *client,
			   enum lsm_detection_mode mode,
			   bool detectfailure)
{
	int rc = 0;

	if (!client->confidence_levels) {
		/*
		 * It is possible that confidence levels are
		 * not provided. This is not a error condition.
		 * Return gracefully without any error
		 */
		pr_debug("%s: no conf levels to set\n",
			__func__);
		return rc;
	}

	if (mode == LSM_MODE_KEYWORD_ONLY_DETECTION) {
		client->mode = 0x01;
	} else if (mode == LSM_MODE_USER_KEYWORD_DETECTION) {
		client->mode = 0x03;
	} else {
		pr_err("%s: Incorrect detection mode %d\n", __func__, mode);
		rc = -EINVAL;
		goto err_ret;
	}
	client->mode |= detectfailure << 2;
	client->connect_to_port = get_lsm_port();

	rc = q6lsm_set_params(client);
	if (rc < 0) {
		pr_err("%s: Failed to set lsm config params %d\n",
			__func__, rc);
		goto err_ret;
	}
	rc = q6lsm_send_cal(client);
	if (rc < 0) {
		pr_err("%s: Failed to send calibration data %d\n",
			__func__, rc);
		goto err_ret;
	}

err_ret:
	return rc;
}

int q6lsm_register_sound_model(struct lsm_client *client,
			       enum lsm_detection_mode mode,
			       bool detectfailure)
{
	int rc;
	struct lsm_cmd_reg_snd_model cmd;

	memset(&cmd, 0, sizeof(cmd));
	rc = q6lsm_set_data(client, mode, detectfailure);
	if (rc) {
		pr_err("%s: Failed to set lsm data, err = %d\n",
			__func__, rc);
		return rc;
	}

	q6lsm_add_hdr(client, &cmd.hdr, sizeof(cmd), true);
	cmd.hdr.opcode = LSM_SESSION_CMD_REGISTER_SOUND_MODEL;
	cmd.model_addr_lsw = lower_32_bits(client->sound_model.phys);
	cmd.model_addr_msw = upper_32_bits(client->sound_model.phys);
	cmd.model_size = client->sound_model.size;
	/* read updated mem_map_handle by q6lsm_mmapcallback */
	rmb();
	cmd.mem_map_handle = client->sound_model.mem_map_handle;

	pr_debug("%s: addr %pa, size %d, handle 0x%x\n", __func__,
		&client->sound_model.phys, cmd.model_size, cmd.mem_map_handle);
	rc = q6lsm_apr_send_pkt(client, client->apr, &cmd, true, NULL);
	if (rc)
		pr_err("%s: Failed cmd op[0x%x]rc[%d]\n", __func__,
		       cmd.hdr.opcode, rc);
	else
		pr_debug("%s: Register sound model succeeded\n", __func__);

	return rc;
}

int q6lsm_deregister_sound_model(struct lsm_client *client)
{
	int rc;
	struct lsm_cmd_reg_snd_model cmd;

	if (!client) {
		pr_err("APR handle NULL\n");
		return -EINVAL;
	}
	if (!client->apr) {
		pr_err("APR client handle NULL\n");
		return -EINVAL;
	}

	if (CHECK_SESSION(client->session)) {
		pr_err("%s: session[%d]", __func__, client->session);
		return -EINVAL;
	}

	memset(&cmd, 0, sizeof(cmd));
	q6lsm_add_hdr(client, &cmd.hdr, sizeof(cmd.hdr), false);
	cmd.hdr.opcode = LSM_SESSION_CMD_DEREGISTER_SOUND_MODEL;

	rc = q6lsm_apr_send_pkt(client, client->apr, &cmd.hdr, true, NULL);
	if (rc < 0) {
		pr_err("%s: Failed cmd opcode 0x%x, rc %d\n", __func__,
		       cmd.hdr.opcode, rc);
	} else {
		pr_debug("%s: Deregister sound model succeeded\n", __func__);
	}

	q6lsm_snd_model_buf_free(client);

	return rc;
}

static void q6lsm_add_mmaphdr(struct lsm_client *client, struct apr_hdr *hdr,
			      u32 pkt_size, u32 cmd_flg, u32 token)
{
	pr_debug("%s: pkt size=%d cmd_flg=%d session=%d\n", __func__, pkt_size,
		 cmd_flg, client->session);
	hdr->hdr_field = APR_HDR_FIELD(APR_MSG_TYPE_SEQ_CMD,
				       APR_HDR_LEN(APR_HDR_SIZE), APR_PKT_VER);
	hdr->src_port = 0x00;
	hdr->dest_port = client->session;
	if (cmd_flg)
		hdr->token = token;
	hdr->pkt_size = pkt_size;
	return;
}

static int q6lsm_memory_map_regions(struct lsm_client *client,
				    dma_addr_t dma_addr_p, uint32_t dma_buf_sz,
				    uint32_t *mmap_p)
{
	struct avs_cmd_shared_mem_map_regions *mmap_regions = NULL;
	struct avs_shared_map_region_payload *mregions = NULL;
	void *mmap_region_cmd = NULL;
	void *payload = NULL;
	int rc;
	int cmd_size = 0;

	pr_debug("%s: dma_addr_p 0x%pa, dma_buf_sz %d, mmap_p 0x%p, session %d\n",
		__func__, &dma_addr_p, dma_buf_sz, mmap_p,
		client->session);
	if (CHECK_SESSION(client->session)) {
		pr_err("%s: session[%d]", __func__, client->session);
		return -EINVAL;
	}
	cmd_size = sizeof(struct avs_cmd_shared_mem_map_regions) +
		   sizeof(struct avs_shared_map_region_payload);

	mmap_region_cmd = kzalloc(cmd_size, GFP_KERNEL);
	if (!mmap_region_cmd) {
		pr_err("%s: memory allocation failed\n", __func__);
		return -ENOMEM;
	}

	mmap_regions = (struct avs_cmd_shared_mem_map_regions *)mmap_region_cmd;
	q6lsm_add_mmaphdr(client, &mmap_regions->hdr, cmd_size, true,
			  (client->session << 8));

	mmap_regions->hdr.opcode = LSM_SESSION_CMD_SHARED_MEM_MAP_REGIONS;
	mmap_regions->mem_pool_id = ADSP_MEMORY_MAP_SHMEM8_4K_POOL;
	mmap_regions->num_regions = 1;
	mmap_regions->property_flag = 0x00;
	payload = ((u8 *)mmap_region_cmd +
		   sizeof(struct avs_cmd_shared_mem_map_regions));
	mregions = (struct avs_shared_map_region_payload *)payload;

	mregions->shm_addr_lsw = lower_32_bits(dma_addr_p);
	mregions->shm_addr_msw = upper_32_bits(dma_addr_p);
	mregions->mem_size_bytes = dma_buf_sz;

	rc = q6lsm_apr_send_pkt(client, client->mmap_apr, mmap_region_cmd,
				true, mmap_p);
	if (rc)
		pr_err("%s: Failed mmap_regions opcode 0x%x, rc %d\n",
			__func__, mmap_regions->hdr.opcode, rc);

	pr_debug("%s: leave %d\n", __func__, rc);
	kfree(mmap_region_cmd);
	return rc;
}

static int q6lsm_memory_unmap_regions(struct lsm_client *client,
				      uint32_t handle)
{
	struct avs_cmd_shared_mem_unmap_regions unmap;
	int rc = 0;
	int cmd_size = 0;
	if (CHECK_SESSION(client->session)) {
		pr_err("%s: session[%d]", __func__, client->session);
		return -EINVAL;
	}
	cmd_size = sizeof(struct avs_cmd_shared_mem_unmap_regions);
	q6lsm_add_mmaphdr(client, &unmap.hdr, cmd_size,
			  true, (client->session << 8));
	unmap.hdr.opcode = LSM_SESSION_CMD_SHARED_MEM_UNMAP_REGIONS;
	unmap.mem_map_handle = handle;

	pr_debug("%s: unmap handle 0x%x\n", __func__, unmap.mem_map_handle);
	rc = q6lsm_apr_send_pkt(client, client->mmap_apr, &unmap, true,
				NULL);
	if (rc)
		pr_err("%s: Failed mmap_regions opcode 0x%x rc %d\n",
		       __func__, unmap.hdr.opcode, rc);

	return rc;
}

static int q6lsm_send_cal(struct lsm_client *client)
{
	int rc = 0;
	struct lsm_cmd_set_params	params;
	struct cal_block_data		*cal_block = NULL;

	pr_debug("%s: Session id %d\n", __func__, client->session);
	if (CHECK_SESSION(client->session)) {
		pr_err("%s: session[%d]", __func__, client->session);
		return -EINVAL;
	}

	if (lsm_common.cal_data == NULL)
		goto done;

	mutex_lock(&lsm_common.cal_data->lock);
	cal_block = cal_utils_get_only_cal_block(lsm_common.cal_data);
	if (cal_block == NULL)
		goto unlock;

	if (cal_block->cal_data.size <= 0) {
		pr_debug("%s: No cal to send!\n", __func__);
		rc = -EINVAL;
		goto unlock;
	}
	if (cal_block->cal_data.size != client->lsm_cal_size) {
		pr_err("%s: Cal size %zd doesn't match lsm cal size %d\n",
			__func__, cal_block->cal_data.size,
			client->lsm_cal_size);
		rc = -EINVAL;
		goto unlock;
	}
	/* Cache mmap address, only map once or if new addr */
	lsm_common.common_client[client->session].session = client->session;
	q6lsm_add_hdr(client, &params.hdr, sizeof(params), true);
	params.hdr.opcode = LSM_SESSION_CMD_SET_PARAMS;
	params.data_payload_addr_lsw = lower_32_bits(client->lsm_cal_phy_addr);
	params.data_payload_addr_msw = upper_32_bits(client->lsm_cal_phy_addr);
	params.mem_map_handle = client->sound_model.mem_map_handle;
	params.data_payload_size = cal_block->cal_data.size;
	pr_debug("%s: Cal Size = %zd", __func__, cal_block->cal_data.size);
	rc = q6lsm_apr_send_pkt(client, client->apr, &params, true, NULL);
	if (rc)
		pr_err("%s: Failed set_params opcode 0x%x, rc %d\n",
		       __func__, params.hdr.opcode, rc);
unlock:
	mutex_unlock(&lsm_common.cal_data->lock);
done:
	return rc;
}


int q6lsm_snd_model_buf_free(struct lsm_client *client)
{
	int rc;

	pr_debug("%s: Session id %d\n", __func__, client->session);
	if (CHECK_SESSION(client->session)) {
		pr_err("%s: session[%d]", __func__, client->session);
		return -EINVAL;
	}

	mutex_lock(&client->cmd_lock);
	rc = q6lsm_memory_unmap_regions(client,
					client->sound_model.mem_map_handle);
	if (rc < 0)
		pr_err("%s: CMD Memory_unmap_regions failed %d\n",
			__func__, rc);

	if (client->sound_model.data) {
		msm_audio_ion_free(client->sound_model.client,
				 client->sound_model.handle);
		client->sound_model.client = NULL;
		client->sound_model.handle = NULL;
		client->sound_model.data = NULL;
		client->sound_model.phys = 0;
		client->lsm_cal_phy_addr = 0;
		client->lsm_cal_size = 0;
	}
	mutex_unlock(&client->cmd_lock);
	return rc;
}

static struct lsm_client *q6lsm_get_lsm_client(int session_id)
{
	unsigned long flags;
	struct lsm_client *client = NULL;

	spin_lock_irqsave(&lsm_session_lock, flags);
	if (session_id < LSM_MIN_SESSION_ID || session_id > LSM_MAX_SESSION_ID)
		pr_err("%s: Invalid session %d\n", __func__, session_id);
	else if (!lsm_session[session_id])
		pr_err("%s: Not an active session %d\n", __func__, session_id);
	else
		client = lsm_session[session_id];
	spin_unlock_irqrestore(&lsm_session_lock, flags);
	return client;
}

/*
 * q6lsm_mmapcallback : atomic context
 */
static int q6lsm_mmapcallback(struct apr_client_data *data, void *priv)
{
	unsigned long flags;
	uint32_t command;
	uint32_t retcode;
	uint32_t sid;
	const uint32_t *payload = data->payload;
	struct lsm_client *client = NULL;

	if (data->opcode == RESET_EVENTS) {
		sid = (data->token >> 8) & 0x0F;
		pr_debug("%s: SSR event received 0x%x, event 0x%x,\n"
			 "proc 0x%x SID 0x%x\n", __func__, data->opcode,
			 data->reset_event, data->reset_proc, sid);
		lsm_common.common_client[sid].lsm_cal_phy_addr = 0;
		cal_utils_clear_cal_block_q6maps(1, &lsm_common.cal_data);
		return 0;
	}

	command = payload[0];
	retcode = payload[1];
	sid = (data->token >> 8) & 0x0F;
	pr_debug("%s: opcode 0x%x command 0x%x return code 0x%x SID 0x%x\n",
		 __func__, data->opcode, command, retcode, sid);
	client = q6lsm_get_lsm_client(sid);
	if (!client) {
		pr_debug("%s: Session %d already freed\n", __func__, sid);
		return 0;
	}

	switch (data->opcode) {
	case LSM_SESSION_CMDRSP_SHARED_MEM_MAP_REGIONS:
		if (atomic_read(&client->cmd_state) == CMD_STATE_WAIT_RESP) {
			spin_lock_irqsave(&mmap_lock, flags);
			*mmap_handle_p = command;
			/* spin_unlock_irqrestore implies barrier */
			spin_unlock_irqrestore(&mmap_lock, flags);
			atomic_set(&client->cmd_state, CMD_STATE_CLEARED);
			wake_up(&client->cmd_wait);
		}
		break;
	case APR_BASIC_RSP_RESULT:
		switch (command) {
		case LSM_SESSION_CMD_SHARED_MEM_UNMAP_REGIONS:
			atomic_set(&client->cmd_state, CMD_STATE_CLEARED);
			wake_up(&client->cmd_wait);
			break;
		case LSM_SESSION_CMD_SHARED_MEM_MAP_REGIONS:
			if (retcode != 0) {
				/* error state, signal to stop waiting */
				if (atomic_read(&client->cmd_state) ==
					CMD_STATE_WAIT_RESP) {
					spin_lock_irqsave(&mmap_lock, flags);
					/* implies barrier */
					spin_unlock_irqrestore(&mmap_lock,
						flags);
					atomic_set(&client->cmd_state,
						CMD_STATE_CLEARED);
					wake_up(&client->cmd_wait);
				}
			}
		break;
		default:
			pr_warn("%s: Unexpected command 0x%x\n", __func__,
				command);
		}
	default:
		pr_debug("%s: command 0x%x return code 0x%x opcode 0x%x\n",
			 __func__, command, retcode, data->opcode);
		break;
	}
	if (client->cb)
		client->cb(data->opcode, data->token,
			   data->payload, client->priv);
	return 0;
}

int q6lsm_snd_model_buf_alloc(struct lsm_client *client, size_t len)
{
	int rc = -EINVAL;
	struct cal_block_data		*cal_block = NULL;

	size_t pad_zero = 0, total_mem = 0;

	if (!client || len <= LSM_ALIGN_BOUNDARY)
		return rc;

	mutex_lock(&client->cmd_lock);

	mutex_lock(&lsm_common.cal_data->lock);
	cal_block = cal_utils_get_only_cal_block(lsm_common.cal_data);
	if (cal_block == NULL)
		goto fail;

	pr_debug("%s:Snd Model len = %zd cal size %zd phys addr %pa", __func__,
	 len, cal_block->cal_data.size, &cal_block->cal_data.paddr);
	if (!cal_block->cal_data.paddr) {
		pr_err("%s: No LSM calibration set for session", __func__);
		rc = -EINVAL;
		goto fail;
	}
	if (!client->sound_model.data) {
		client->sound_model.size = len;
		pad_zero = (LSM_ALIGN_BOUNDARY -
			    (len % LSM_ALIGN_BOUNDARY));
		if ((len > SIZE_MAX - pad_zero) ||
		    (len + pad_zero >
		     SIZE_MAX - cal_block->cal_data.size)) {
			pr_err("%s: invalid allocation size, len = %zd, pad_zero =%zd, cal_size = %zd\n",
				__func__, len, pad_zero,
				cal_block->cal_data.size);
			rc = -EINVAL;
			goto fail;
		}

		total_mem = PAGE_ALIGN(pad_zero + len +
			cal_block->cal_data.size);
		pr_debug("%s: Pad zeros sound model %zd Total mem %zd\n",
				 __func__, pad_zero, total_mem);
		rc = msm_audio_ion_alloc("lsm_client",
				&client->sound_model.client,
				&client->sound_model.handle,
				total_mem,
				&client->sound_model.phys,
				&len,
				&client->sound_model.data);
		if (rc) {
			pr_err("%s: Audio ION alloc is failed, rc = %d\n",
				__func__, rc);
			goto fail;
		}
	pr_debug("%s: Length = %zd\n", __func__, len);
	client->lsm_cal_phy_addr = (pad_zero +
				    client->sound_model.phys +
				    client->sound_model.size);
	client->lsm_cal_size = cal_block->cal_data.size;
	memcpy((client->sound_model.data + pad_zero +
		client->sound_model.size),
	       (uint32_t *)cal_block->cal_data.kvaddr, client->lsm_cal_size);
	pr_debug("%s: Copy cal start virt_addr %p phy_addr %pa\n"
			 "Offset cal virtual Addr %p\n", __func__,
			 client->sound_model.data, &client->sound_model.phys,
			 (pad_zero + client->sound_model.data +
			 client->sound_model.size));
	} else {
		pr_err("%s: sound model busy\n", __func__);
		rc = -EBUSY;
		goto fail;
	}
	mutex_unlock(&lsm_common.cal_data->lock);
	mutex_unlock(&client->cmd_lock);

	rc = q6lsm_memory_map_regions(client, client->sound_model.phys,
				      len,
				      &client->sound_model.mem_map_handle);
	if (rc < 0) {
		pr_err("%s: CMD Memory_map_regions failed %d\n", __func__, rc);
		goto exit;
	}

	return 0;
fail:
	mutex_unlock(&lsm_common.cal_data->lock);
	mutex_unlock(&client->cmd_lock);
exit:
	q6lsm_snd_model_buf_free(client);
	return rc;
}

static int q6lsm_cmd(struct lsm_client *client, int opcode, bool wait)
{
	struct apr_hdr hdr;
	int rc;

	pr_debug("%s: enter opcode %x wait %d\n", __func__, opcode, wait);
	q6lsm_add_hdr(client, &hdr, sizeof(hdr), true);
	switch (opcode) {
	case LSM_SESSION_CMD_START:
	case LSM_SESSION_CMD_STOP:
	case LSM_SESSION_CMD_CLOSE_TX:
	case LSM_SESSION_CMD_EOB:
		hdr.opcode = opcode;
		break;
	default:
		pr_err("%s: Invalid opcode 0x%x\n", __func__, opcode);
		return -EINVAL;
	}
	rc = q6lsm_apr_send_pkt(client, client->apr, &hdr, wait, NULL);
	if (rc)
		pr_err("%s: Failed commmand 0x%x\n", __func__, hdr.opcode);

	pr_debug("%s: leave %d\n", __func__, rc);
	return rc;
}

int q6lsm_start(struct lsm_client *client, bool wait)
{
	return q6lsm_cmd(client, LSM_SESSION_CMD_START, wait);
}

int q6lsm_stop(struct lsm_client *client, bool wait)
{
	return q6lsm_cmd(client, LSM_SESSION_CMD_STOP, wait);
}

int q6lsm_close(struct lsm_client *client)
{
	return q6lsm_cmd(client, LSM_SESSION_CMD_CLOSE_TX, true);
}

int q6lsm_lab_control(struct lsm_client *client, u32 enable)
{
	int rc = 0;
	struct lsm_params_lab_enable lab_enable;
	struct lsm_params_lab_config lab_config;

	if (!client) {
		pr_err("%s: invalid param client %p\n", __func__, client);
		return -EINVAL;
	}
	/* enable/disable lab on dsp */
	q6lsm_add_hdr(client, &lab_enable.hdr, sizeof(lab_enable), true);
	lab_enable.hdr.opcode = LSM_SESSION_CMD_SET_PARAMS;
	lab_enable.data_payload_size = sizeof(struct lsm_lab_enable);
	lab_enable.data_payload_addr_lsw = 0;
	lab_enable.data_payload_addr_msw = 0;
	lab_enable.mem_map_handle = 0;
	lab_enable.lab_enable.common.module_id = LSM_MODULE_ID_LAB;
	lab_enable.lab_enable.common.param_id = LSM_PARAM_ID_LAB_ENABLE;
	lab_enable.lab_enable.common.param_size = sizeof(struct lsm_lab_enable)
	- sizeof(struct lsm_param_payload_common);
	lab_enable.lab_enable.enable = (enable) ? 1 : 0;
	rc = q6lsm_apr_send_pkt(client, client->apr, &lab_enable, true, NULL);
	if (rc) {
		pr_err("%s: Lab enable failed rc %d\n", __func__, rc);
		return rc;
	}
	if (!enable)
		goto exit;
	/* lab session is being enabled set the config values */
	q6lsm_add_hdr(client, &lab_config.hdr, sizeof(lab_config), true);
	lab_config.hdr.opcode = LSM_SESSION_CMD_SET_PARAMS;
	lab_config.data_payload_size = sizeof(struct lsm_lab_config);
	lab_config.data_payload_addr_lsw = 0;
	lab_config.data_payload_addr_msw = 0;
	lab_config.mem_map_handle = 0;
	lab_config.lab_config.common.module_id = LSM_MODULE_ID_LAB;
	lab_config.lab_config.common.param_id = LSM_PARAM_ID_LAB_CONFIG;
	lab_config.lab_config.common.param_size = sizeof(struct lsm_lab_config)
	- sizeof(struct lsm_param_payload_common);
	lab_config.lab_config.minor_version = 1;
	lab_config.lab_config.wake_up_latency_ms = 250;
	rc = q6lsm_apr_send_pkt(client, client->apr, &lab_config, true, NULL);
	if (rc) {
		pr_err("%s: Lab config failed rc %d disable lab\n",
		 __func__, rc);
		/* Lab config failed disable lab */
		lab_enable.lab_enable.enable = 0;
		if (q6lsm_apr_send_pkt(client, client->apr,
			&lab_enable, true, NULL))
			pr_err("%s: Lab disable failed\n", __func__);
	}
exit:
	return rc;
}

int q6lsm_stop_lab(struct lsm_client *client)
{
	int rc = 0;
	if (!client) {
		pr_err("%s: invalid param client %p\n", __func__, client);
		return -EINVAL;
	}
	rc = q6lsm_cmd(client, LSM_SESSION_CMD_EOB, true);
	if (rc)
		pr_err("%s: Lab stop failed %d\n", __func__, rc);
	return rc;
}

int q6lsm_read(struct lsm_client *client, struct lsm_cmd_read *read)
{
	int rc = 0;
	if (!client || !read) {
		pr_err("%s: Invalid params client %p read %p\n", __func__,
			client, read);
		return -EINVAL;
	}
	pr_debug("%s: read call memmap handle %x address %x%x size %d\n",
		 __func__, read->mem_map_handle, read->buf_addr_msw,
		read->buf_addr_lsw, read->buf_size);
	q6lsm_add_hdr(client, &read->hdr, sizeof(struct lsm_cmd_read), true);
	read->hdr.opcode = LSM_SESSION_CMD_READ;
	rc = q6lsm_apr_send_pkt(client, client->apr, read, false, NULL);
	if (rc)
		pr_err("%s: read buffer call failed rc %d\n", __func__, rc);
	return rc;
}

int q6lsm_lab_buffer_alloc(struct lsm_client *client, bool alloc)
{
	int ret = 0, i = 0;
	size_t allocate_size = 0, len = 0;
	if (!client) {
		pr_err("%s: invalid client\n", __func__);
		return -EINVAL;
	}
	if (alloc) {
		if (client->lab_buffer) {
			pr_err("%s: buffers are allocated period count %d period size %d\n",
				__func__,
				client->hw_params.period_count,
				client->hw_params.buf_sz);
			return -EINVAL;
		}
		allocate_size = client->hw_params.period_count *
				client->hw_params.buf_sz;
		allocate_size = PAGE_ALIGN(allocate_size);
		client->lab_buffer =
			kzalloc(sizeof(struct lsm_lab_buffer) *
			client->hw_params.period_count, GFP_KERNEL);
		if (!client->lab_buffer) {
			pr_err("%s: memory allocation for lab buffer failed count %d\n"
				, __func__,
				client->hw_params.period_count);
			return -ENOMEM;
		}
		ret = msm_audio_ion_alloc("lsm_lab",
			&client->lab_buffer[0].client,
			&client->lab_buffer[0].handle,
			allocate_size, &client->lab_buffer[0].phys,
			&len,
			&client->lab_buffer[0].data);
		if (ret)
			pr_err("%s: ion alloc failed ret %d size %zd\n",
				__func__, ret, allocate_size);
		else {
			ret = q6lsm_memory_map_regions(client,
				client->lab_buffer[0].phys, len,
				&client->lab_buffer[0].mem_map_handle);
			if (ret) {
				pr_err("%s: memory map filed ret %d size %zd\n",
				__func__, ret, len);
				msm_audio_ion_free(
				client->lab_buffer[0].client,
				client->lab_buffer[0].handle);
			}
		}
		if (ret) {
			pr_err("%s: alloc lab buffer failed ret %d\n",
				__func__, ret);
			kfree(client->lab_buffer);
			client->lab_buffer = NULL;
		} else {
			pr_debug("%s: Memory map handle %x phys %pa size %d\n",
				__func__,
				client->lab_buffer[0].mem_map_handle,
				&client->lab_buffer[0].phys,
				client->hw_params.buf_sz);
			for (i = 0; i < client->hw_params.period_count; i++) {
				client->lab_buffer[i].phys =
				client->lab_buffer[0].phys +
				(i * client->hw_params.buf_sz);
				client->lab_buffer[i].size =
				client->hw_params.buf_sz;
				client->lab_buffer[i].data =
				(u8 *)(client->lab_buffer[0].data) +
				(i * client->hw_params.buf_sz);
				client->lab_buffer[i].mem_map_handle =
				client->lab_buffer[0].mem_map_handle;
			}
		}
	} else {
		ret = q6lsm_memory_unmap_regions(client,
			client->lab_buffer[0].mem_map_handle);
		if (!ret)
			msm_audio_ion_free(
			client->lab_buffer[0].client,
			client->lab_buffer[0].handle);
		else
			pr_err("%s: unmap failed not freeing memory\n",
			__func__);
		kfree(client->lab_buffer);
		client->lab_buffer = NULL;
	}
	return ret;
}

static int q6lsm_alloc_cal(int32_t cal_type,
				size_t data_size, void *data)
{
	int				ret = 0;
	pr_debug("%s:\n", __func__);

	ret = cal_utils_alloc_cal(data_size, data,
		lsm_common.cal_data, 0, NULL);
	if (ret < 0) {
		pr_err("%s: cal_utils_alloc_block failed, ret = %d, cal type = %d!\n",
			__func__, ret, cal_type);
		ret = -EINVAL;
		goto done;
	}
done:
	return ret;
}

static int q6lsm_dealloc_cal(int32_t cal_type,
				size_t data_size, void *data)
{
	int				ret = 0;
	pr_debug("%s:\n", __func__);

	ret = cal_utils_dealloc_cal(data_size, data,
		lsm_common.cal_data);
	if (ret < 0) {
		pr_err("%s: cal_utils_dealloc_block failed, ret = %d, cal type = %d!\n",
			__func__, ret, cal_type);
		ret = -EINVAL;
		goto done;
	}
done:
	return ret;
}

static int q6lsm_set_cal(int32_t cal_type,
			size_t data_size, void *data)
{
	int				ret = 0;
	pr_debug("%s:\n", __func__);

	ret = cal_utils_set_cal(data_size, data,
		lsm_common.cal_data, 0, NULL);
	if (ret < 0) {
		pr_err("%s: cal_utils_set_cal failed, ret = %d, cal type = %d!\n",
			__func__, ret, cal_type);
		ret = -EINVAL;
		goto done;
	}
done:
	return ret;
}

static void lsm_delete_cal_data(void)
{
	pr_debug("%s:\n", __func__);

	cal_utils_destroy_cal_types(1, &lsm_common.cal_data);
	return;
}

static int q6lsm_init_cal_data(void)
{
	int ret = 0;
	struct cal_type_info	cal_type_info = {
		{LSM_CAL_TYPE,
		{q6lsm_alloc_cal, q6lsm_dealloc_cal, NULL,
		q6lsm_set_cal, NULL, NULL} },
		{NULL, NULL, cal_utils_match_buf_num}
	};
	pr_debug("%s:\n", __func__);

	ret = cal_utils_create_cal_types(1, &lsm_common.cal_data,
		&cal_type_info);
	if (ret < 0) {
		pr_err("%s: could not create cal type!\n",
			__func__);
		ret = -EINVAL;
		goto err;
	}

	return ret;
err:
	lsm_delete_cal_data();
	return ret;
}

static int __init q6lsm_init(void)
{
	int i = 0;
	pr_debug("%s:\n", __func__);
	spin_lock_init(&lsm_session_lock);
	spin_lock_init(&mmap_lock);
	mutex_init(&lsm_common.apr_lock);
	for (; i <= LSM_MAX_SESSION_ID; i++) {
		lsm_common.common_client[i].session = LSM_CONTROL_SESSION;
		init_waitqueue_head(&lsm_common.common_client[i].cmd_wait);
		mutex_init(&lsm_common.common_client[i].cmd_lock);
		atomic_set(&lsm_common.common_client[i].cmd_state,
			   CMD_STATE_CLEARED);
	}

	if (q6lsm_init_cal_data())
		pr_err("%s: could not init cal data!\n", __func__);

	return 0;
}

static void __exit q6lsm_exit(void)
{
	lsm_delete_cal_data();
}

device_initcall(q6lsm_init);
__exitcall(q6lsm_exit);
