/* Production WMI function extraction; mocks model DMA and transport ownership. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t A_UINT32;
typedef uint32_t u_int32_t;
typedef int QDF_STATUS;
enum {
	QDF_STATUS_SUCCESS, QDF_STATUS_E_FAILURE, QDF_STATUS_E_INVAL,
	QDF_STATUS_E_NOMEM, QDF_STATUS_E_NOSUPPORT, MAP_ERROR = 81,
	SEND_ERROR = 82, REGISTER_ERROR = 83,
};
#define QDF_IS_STATUS_ERROR(s) ((s) != QDF_STATUS_SUCCESS)
#define roundup(n, a) (((n) + (a) - 1) / (a) * (a))
#define qdf_mem_zero(p, n) memset((p), 0, (n))
#define qdf_mem_copy(p, s, n) memcpy((p), (s), (n))
#define OS_MEMCPY(p, s, n) memmove((p), (s), (n))
#define qdf_le32_to_cpu(v) __builtin_bswap32(v)
#define QDF_DMA_TO_DEVICE 1
#define wmi_err(...) do { } while (0)
#define wmi_mtrace(...) do { } while (0)
#define wmi_mgmt_cmd_record(...) do { } while (0)
#define WMI_OFFCHAN_DATA_TX_SEND_CMDID 0x7009
enum { wmi_service_offchan_tx_wmi = 123,
	wmi_offchan_data_tx_completion_event = 0x7010 };

static unsigned int assertions;
#define CHECK(x) do { assertions++; assert(x); } while (0)

/* INSERT_DEFINITIONS */

struct frame {
	uint8_t *data;
	unsigned int len, fragments;
	bool nonlinear, mapped;
	uint64_t dma_addr;
};
struct wmi_ops;
struct wmi_handle {
	struct wmi_ops *ops;
	bool service;
};
typedef struct wmi_handle *wmi_unified_t;
typedef int (*wmi_unified_event_handler)(void *, uint8_t *, uint32_t);
struct wmi_ops {
	QDF_STATUS (*send_offchan_data_tx_cmd)(wmi_unified_t,
					struct wmi_offchan_data_tx_params *);
	QDF_STATUS (*extract_offchan_data_tx_compl_param)(wmi_unified_t, void *,
				struct wmi_host_offchan_data_tx_compl_event *);
	uint32_t (*convert_target_pdev_id_to_host)(wmi_unified_t, uint32_t);
};
typedef struct {
	wmi_offchan_data_tx_compl_event_fixed_param *fixed_param;
	uint32_t num_fixed_param, is_allocated_fixed_param;
} WMI_OFFCHAN_DATA_TX_COMPLETION_EVENTID_param_tlvs;
struct command { void *data; int len; };
typedef struct command *wmi_buf_t;

static struct {
	bool alloc_fail;
	QDF_STATUS map_status, send_status, register_status, unregister_status;
	unsigned int allocs, maps, unmaps, sends, frees, releases;
	unsigned int registrations, unregistrations;
	bool registered;
	wmi_unified_event_handler callback;
	uint8_t rx_ctx;
	_Alignas(uint32_t) uint8_t bytes[4096];
	unsigned int len;
} mock;

static unsigned int qdf_nbuf_len(struct frame *frame) { return frame->len; }
static bool qdf_nbuf_is_nonlinear(struct frame *frame) { return frame->nonlinear; }
static unsigned int qdf_nbuf_get_num_frags(struct frame *frame)
{
	return frame->fragments;
}
static QDF_STATUS qdf_nbuf_map_single(void *ctx, struct frame *frame, int direction)
{
	CHECK(ctx && direction == QDF_DMA_TO_DEVICE && !frame->mapped);
	mock.maps++;
	if (!mock.map_status)
		frame->mapped = true;
	return mock.map_status;
}
static void qdf_nbuf_unmap_single(void *ctx, struct frame *frame, int direction)
{
	CHECK(ctx && direction == QDF_DMA_TO_DEVICE && frame->mapped);
	mock.unmaps++;
	frame->mapped = false;
}
static uint64_t qdf_nbuf_get_frag_paddr(struct frame *frame, int fragment)
{
	CHECK(frame->mapped && !fragment);
	return frame->dma_addr;
}
static wmi_buf_t wmi_buf_alloc(wmi_unified_t handle, int len)
{
	CHECK(handle && len > 0);
	mock.allocs++;
	if (mock.alloc_fail)
		return NULL;
	wmi_buf_t buf = malloc(sizeof(*buf));
	CHECK(buf != NULL);
	buf->data = malloc(len);
	CHECK(buf->data != NULL);
	buf->len = len;
	memset(buf->data, 0xa5, len);
	return buf;
}
static void *wmi_buf_data(wmi_buf_t buf) { return buf->data; }
static void wmi_buf_free(wmi_buf_t buf)
{
	mock.frees++;
	free(buf->data);
	free(buf);
}
static QDF_STATUS wmi_unified_cmd_send(wmi_unified_t handle, wmi_buf_t buf,
				     int len, int command)
{
	CHECK(handle && command == WMI_OFFCHAN_DATA_TX_SEND_CMDID);
	CHECK(len == buf->len && (unsigned int)len <= sizeof(mock.bytes));
	mock.sends++;
	mock.len = len;
	memcpy(mock.bytes, buf->data, len);
	if (!mock.send_status) {
		/* Success consumes only the command buffer, never the caller frame. */
		free(buf->data);
		free(buf);
	}
	return mock.send_status;
}
static bool wmi_service_enabled(wmi_unified_t handle, uint32_t service)
{
	CHECK(service == wmi_service_offchan_tx_wmi);
	return handle->service;
}
static QDF_STATUS wmi_unified_register_event_handler(wmi_unified_t handle,
		uint32_t event, wmi_unified_event_handler handler, uint8_t ctx)
{
	CHECK(handle && event == wmi_offchan_data_tx_completion_event && handler);
	mock.registrations++;
	if (mock.register_status)
		return mock.register_status;
	if (mock.registered)
		return QDF_STATUS_E_FAILURE;
	mock.registered = true;
	mock.callback = handler;
	mock.rx_ctx = ctx;
	return QDF_STATUS_SUCCESS;
}
static QDF_STATUS wmi_unified_unregister_event_handler(wmi_unified_t handle,
						      uint32_t event)
{
	CHECK(handle && event == wmi_offchan_data_tx_completion_event);
	mock.unregistrations++;
	if (mock.unregister_status)
		return mock.unregister_status;
	if (!mock.registered)
		return QDF_STATUS_E_FAILURE;
	mock.registered = false;
	return QDF_STATUS_SUCCESS;
}
static uint32_t convert_pdev(wmi_unified_t handle, uint32_t id)
{
	CHECK(handle && id >= 1 && id <= 3);
	return id - 1;
}

/* INSERT_FUNCTIONS */

static struct wmi_ops ops = {
	.send_offchan_data_tx_cmd = send_offchan_data_tx_cmd_tlv,
	.extract_offchan_data_tx_compl_param = extract_offchan_data_tx_compl_param_tlv,
	.convert_target_pdev_id_to_host = convert_pdev,
};
static struct wmi_handle handle = { .ops = &ops, .service = true };

static struct wmi_offchan_data_tx_params setup(struct frame *frame, unsigned int len)
{
	memset(&mock, 0, sizeof(mock));
	*frame = (struct frame){ .len = len, .fragments = 1,
		.dma_addr = 0x12345678, .data = malloc(len) };
	CHECK(frame->data);
	for (unsigned int i = 0; i < len; i++)
		frame->data[i] = (uint8_t)(i * 3 + 1);
	return (struct wmi_offchan_data_tx_params){ .tx_frame = frame,
		.frm_len = len, .vdev_id = 7, .desc_id = 0x321,
		.chanfreq = 2437, .pdata = frame->data, .qdf_ctx = frame };
}
static void caller_release(struct frame *frame)
{
	CHECK(!frame->mapped);
	mock.releases++;
	free(frame->data);
}
static void assert_no_transfer(void)
{
	CHECK(!mock.maps && !mock.unmaps && !mock.sends && !mock.releases);
}
static void validate_command(struct wmi_offchan_data_tx_params *param)
{
	wmi_offchan_data_tx_send_cmd_fixed_param *cmd = (void *)mock.bytes;
	unsigned int prefix_len = param->frm_len < mgmt_tx_dl_frm_len ?
			param->frm_len : mgmt_tx_dl_frm_len;
	uint32_t *array = (void *)(cmd + 1);
	uint8_t *prefix = (void *)(array + 1);
	wmi_tx_send_params *tx = (void *)(prefix + roundup(prefix_len, 4));
	CHECK(WMITLV_GET_TLVTAG(cmd->tlv_header) ==
		WMITLV_TAG_STRUC_wmi_offchan_data_tx_send_cmd_fixed_param);
	CHECK(WMITLV_GET_TLVLEN(cmd->tlv_header) == sizeof(*cmd) - 4);
	CHECK(cmd->vdev_id == 7 && cmd->desc_id == 0x321 && cmd->chanfreq == 2437);
	CHECK(cmd->frame_len == param->frm_len && cmd->buf_len == prefix_len);
	CHECK(cmd->paddr_lo == 0x12345678 && cmd->tx_params_valid == param->tx_params_valid);
#ifdef HTT_PADDR64
	CHECK(cmd->paddr_hi == (((struct frame *)param->tx_frame)->dma_addr >> 32));
#else
	CHECK(!cmd->paddr_hi);
#endif
	CHECK(WMITLV_GET_TLVTAG(*array) == WMITLV_TAG_ARRAY_BYTE);
	CHECK(WMITLV_GET_TLVLEN(*array) == roundup(prefix_len, 4));
#ifdef BIG_ENDIAN_HOST
	/* Model the copy engine word swap to compare bytes as received by target. */
	for (unsigned int i = 0; i < roundup(prefix_len, 4); i += 4) {
		uint32_t value;
		memcpy(&value, prefix + i, 4);
		value = __builtin_bswap32(value);
		memcpy(prefix + i, &value, 4);
	}
#endif
	CHECK(!memcmp(prefix, param->pdata, prefix_len));
	for (unsigned int i = prefix_len; i < roundup(prefix_len, 4); i++)
		CHECK(!prefix[i]);
	CHECK(mock.len == sizeof(*cmd) + 4 + roundup(prefix_len, 4) + sizeof(*tx));
	CHECK(WMITLV_GET_TLVTAG(tx->tlv_header) == WMITLV_TAG_STRUC_wmi_tx_send_params);
	CHECK(WMITLV_GET_TLVLEN(tx->tlv_header) == sizeof(*tx) - 4);
	if (!param->tx_params_valid) {
		CHECK(!tx->tx_param_dword0 && !tx->tx_param_dword1);
	} else {
		/* Independent wire expectations include every field and reserved zeros. */
		CHECK(tx->tx_param_dword0 == (0x19u | (0x345u << 8) | (2u << 20) | (4u << 28)));
		CHECK(tx->tx_param_dword1 == (3u | (5u << 8) | (2u << 15) |
			(1u << 20) | (1u << 21) | (1u << 22) | (6u << 23)));
	}
}
static void test_submission(void)
{
	struct frame frame;
	struct wmi_offchan_data_tx_params param = setup(&frame, 67);
	mock.alloc_fail = true;
	CHECK(wmi_offchan_data_tx_cmd_send(&handle, &param) == QDF_STATUS_E_NOMEM);
	CHECK(mock.allocs == 1 && !mock.frees);
	assert_no_transfer();
	caller_release(&frame);

	param = setup(&frame, 67);
	mock.map_status = MAP_ERROR;
	CHECK(wmi_offchan_data_tx_cmd_send(&handle, &param) == MAP_ERROR);
	CHECK(mock.maps == 1 && !mock.unmaps && !mock.sends && mock.frees == 1);
	CHECK(!frame.mapped && !mock.releases);
	caller_release(&frame);

	param = setup(&frame, 67);
	mock.send_status = SEND_ERROR;
	CHECK(wmi_offchan_data_tx_cmd_send(&handle, &param) == SEND_ERROR);
	CHECK(mock.maps == 1 && mock.unmaps == 1 && mock.sends == 1 && mock.frees == 1);
	CHECK(!frame.mapped && !mock.releases);
	caller_release(&frame);

	/* Exact-size allocations expose source overreads in partial-word prefixes. */
	for (unsigned int len = 1; len <= 70; len++) {
		param = setup(&frame, len);
		CHECK(wmi_offchan_data_tx_cmd_send(&handle, &param) == QDF_STATUS_SUCCESS);
		CHECK(frame.mapped && mock.maps == 1 && !mock.unmaps && !mock.frees);
		validate_command(&param);
		CHECK(!mock.releases);
		qdf_nbuf_unmap_single(param.qdf_ctx, &frame, QDF_DMA_TO_DEVICE);
		caller_release(&frame);
	}
	param = setup(&frame, 33);
	param.tx_params_valid = true;
	param.tx_param = (struct tx_send_params){ .pwr = 0x19, .mcs_mask = 0x345,
		.nss_mask = 2, .retry_limit = 4, .chain_mask = 3, .bw_mask = 5,
		.preamble_type = 2, .frame_type = 1, .cfr_enable = 1,
		.en_beamforming = 1, .retry_limit_ext = 6, .reserved = 0x3f };
	CHECK(wmi_offchan_data_tx_cmd_send(&handle, &param) == QDF_STATUS_SUCCESS);
	validate_command(&param);
	qdf_nbuf_unmap_single(param.qdf_ctx, &frame, QDF_DMA_TO_DEVICE);
	caller_release(&frame);

	param = setup(&frame, 16);
#ifdef HTT_PADDR64
	frame.dma_addr = (1ull << 37);
#else
	frame.dma_addr = (1ull << 32);
#endif
	CHECK(wmi_offchan_data_tx_cmd_send(&handle, &param) == QDF_STATUS_E_INVAL);
	CHECK(mock.maps == 1 && mock.unmaps == 1 && !mock.sends && mock.frees == 1);
	caller_release(&frame);
#ifdef HTT_PADDR64
	param = setup(&frame, 16);
	frame.dma_addr |= 0x1full << 32;
	CHECK(wmi_offchan_data_tx_cmd_send(&handle, &param) == QDF_STATUS_SUCCESS);
	validate_command(&param);
	qdf_nbuf_unmap_single(param.qdf_ctx, &frame, QDF_DMA_TO_DEVICE);
	caller_release(&frame);
#endif

	for (int invalid = 0; invalid < 10; invalid++) {
		param = setup(&frame, 16);
		switch (invalid) {
		case 0: param.tx_frame = NULL; break;
		case 1: param.pdata = NULL; break;
		case 2: param.qdf_ctx = NULL; break;
		case 3: param.frm_len = 0; break;
		case 4: param.frm_len = 17; break;
		case 5: frame.nonlinear = true; break;
		case 6: frame.fragments = 2; break;
		case 7: frame.fragments = 0; break;
		case 8: frame.len = 0; break;
		case 9: param.desc_id = 0x10000; break;
		}
		CHECK(wmi_offchan_data_tx_cmd_send(&handle, &param) == QDF_STATUS_E_INVAL);
		assert_no_transfer();
		CHECK(!mock.allocs);
		caller_release(&frame);
	}
	CHECK(wmi_offchan_data_tx_cmd_send(NULL, NULL) == QDF_STATUS_E_INVAL);
	CHECK(wmi_offchan_data_tx_cmd_send(&handle, NULL) == QDF_STATUS_E_INVAL);
	struct wmi_handle no_ops = { 0 };
	CHECK(wmi_offchan_data_tx_cmd_send(&no_ops, &param) == QDF_STATUS_E_INVAL);
}
static void assert_cleared(struct wmi_host_offchan_data_tx_compl_event *event)
{
	CHECK(!event->desc_id && !event->status && !event->pdev_id);
}
static QDF_STATUS failing_decoder(wmi_unified_t wmi, void *buf,
				struct wmi_host_offchan_data_tx_compl_event *event)
{
	CHECK(wmi && buf);
	memset(event, 0xee, sizeof(*event));
	return QDF_STATUS_E_FAILURE;
}
static int completion_handler(void *ctx, uint8_t *buf, uint32_t len)
{
	(void)ctx; (void)buf; (void)len;
	return 0;
}
static void test_completion_and_registration(void)
{
	struct frame frame;
	struct wmi_offchan_data_tx_params param = setup(&frame, 31);
	struct wmi_host_offchan_data_tx_compl_event decoded;
	wmi_offchan_data_tx_compl_event_fixed_param wire = {
		.desc_id = 0x321, .status = 3, .pdev_id = 2, .ppdu_id = 0xffffffff };
	WMI_OFFCHAN_DATA_TX_COMPLETION_EVENTID_param_tlvs event = { .fixed_param = &wire };
	WMITLV_SET_HDR(&wire.tlv_header,
		WMITLV_TAG_STRUC_wmi_offchan_data_tx_compl_event_fixed_param,
		WMITLV_GET_STRUCT_TLVLEN(wmi_offchan_data_tx_compl_event_fixed_param));
	CHECK(sizeof(decoded) == 3 * sizeof(uint32_t));
	CHECK(wmi_offchan_data_tx_cmd_send(&handle, &param) == QDF_STATUS_SUCCESS);
	CHECK(wmi_offchan_data_tx_completion_register(&handle, completion_handler, 4) ==
		QDF_STATUS_SUCCESS);
	CHECK(mock.registrations == 1 && mock.callback == completion_handler && mock.rx_ctx == 4);
	CHECK(wmi_offchan_data_tx_completion_register(&handle, completion_handler, 4) ==
		QDF_STATUS_E_FAILURE);
	CHECK(wmi_extract_offchan_data_tx_compl_param(&handle, &event, &decoded) ==
		QDF_STATUS_SUCCESS);
	CHECK(decoded.desc_id == param.desc_id && decoded.status == 3 && decoded.pdev_id == 1);
	CHECK(frame.mapped && !mock.unmaps && !mock.releases);
	CHECK(wmi_offchan_data_tx_completion_unregister(&handle) == QDF_STATUS_SUCCESS);
	CHECK(frame.mapped && !mock.unmaps && !mock.releases && mock.unregistrations == 1);
	/* The caller performs the actual matching completion ownership transfer. */
	qdf_nbuf_unmap_single(param.qdf_ctx, &frame, QDF_DMA_TO_DEVICE);
	caller_release(&frame);
	CHECK(wmi_offchan_data_tx_completion_unregister(&handle) == QDF_STATUS_E_FAILURE);
	CHECK(wmi_offchan_data_tx_completion_unregister(NULL) == QDF_STATUS_E_INVAL);

	for (int invalid = 0; invalid < 9; invalid++) {
		struct wmi_ops bad_ops = ops;
		struct wmi_handle bad_handle = { .ops = &bad_ops, .service = true };
		WMI_OFFCHAN_DATA_TX_COMPLETION_EVENTID_param_tlvs bad_event = event;
		wmi_offchan_data_tx_compl_event_fixed_param bad_wire = wire;
		bad_event.fixed_param = &bad_wire;
		memset(&decoded, 0xa5, sizeof(decoded));
		void *buf = &bad_event;
		wmi_unified_t wmi = &bad_handle;
		QDF_STATUS expected = QDF_STATUS_E_INVAL;
		switch (invalid) {
		case 0: wmi = NULL; break;
		case 1: bad_handle.ops = NULL; break;
		case 2: buf = NULL; break;
		case 3: bad_event.fixed_param = NULL; break;
		case 4: bad_wire.tlv_header ^= (1u << 16); break;
		case 5: bad_wire.tlv_header--; break;
		case 6: bad_ops.convert_target_pdev_id_to_host = NULL;
			expected = QDF_STATUS_E_NOSUPPORT; break;
		case 7: bad_wire.pdev_id = 0; break;
		case 8: bad_wire.pdev_id = 4; break;
		}
		CHECK(wmi_extract_offchan_data_tx_compl_param(wmi, buf, &decoded) == expected);
		assert_cleared(&decoded);
	}
	CHECK(wmi_extract_offchan_data_tx_compl_param(&handle, &event, NULL) == QDF_STATUS_E_INVAL);
	struct wmi_ops failing_ops = ops;
	struct wmi_handle failing_handle = { .ops = &failing_ops, .service = true };
	failing_ops.extract_offchan_data_tx_compl_param = failing_decoder;
	CHECK(wmi_extract_offchan_data_tx_compl_param(&failing_handle, &event, &decoded) ==
		QDF_STATUS_E_FAILURE);
	assert_cleared(&decoded);
	failing_ops.extract_offchan_data_tx_compl_param = NULL;
	CHECK(wmi_extract_offchan_data_tx_compl_param(&failing_handle, &event, &decoded) ==
		QDF_STATUS_E_NOSUPPORT);
	assert_cleared(&decoded);
	CHECK(wmi_offchan_data_tx_completion_register(&failing_handle, completion_handler, 4) ==
		QDF_STATUS_E_NOSUPPORT);
	failing_ops = ops;
	failing_handle.service = false;
	CHECK(wmi_offchan_data_tx_completion_register(&failing_handle, completion_handler, 4) ==
		QDF_STATUS_E_NOSUPPORT);
	CHECK(wmi_offchan_data_tx_completion_register(NULL, completion_handler, 4) == QDF_STATUS_E_INVAL);
	CHECK(wmi_offchan_data_tx_completion_register(&handle, NULL, 4) == QDF_STATUS_E_INVAL);
	mock.register_status = REGISTER_ERROR;
	CHECK(wmi_offchan_data_tx_completion_register(&handle, completion_handler, 4) == REGISTER_ERROR);
	mock.unregister_status = REGISTER_ERROR;
	CHECK(wmi_offchan_data_tx_completion_unregister(&handle) == REGISTER_ERROR);
}
int main(void)
{
	test_submission();
	test_completion_and_registration();
	printf("%u\n", assertions);
	return 0;
}
