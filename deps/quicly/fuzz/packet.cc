#include "quicly.h"
#include "quicly/frame.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	int ret;
	quicly_decoded_packet_t p;
	ret = quicly_decode_packet(&p, Data, Size);
	if (ret != 0)
		return 0;
	const uint8_t *src = p.payload.base, *end = src + p.payload.len;
	if (p.payload.len == 0)
		return 0;
        uint8_t type_flags = *src++;
        if (type_flags >= QUICLY_FRAME_TYPE_STREAM) {
            quicly_stream_frame_t frame;
            if ((ret = quicly_decode_stream_frame(type_flags, &src, end, &frame)) != 0)
                return 0;
	} else if (type_flags >= QUICLY_FRAME_TYPE_ACK) {
            quicly_ack_frame_t frame;
            if ((ret = quicly_decode_ack_frame(type_flags, &src, end, &frame)) != 0)
                return 0;
	} else {
            switch (type_flags) {
            case QUICLY_FRAME_TYPE_RST_STREAM: {
                quicly_rst_stream_frame_t frame;
                if ((ret = quicly_decode_rst_stream_frame(&src, end, &frame)) != 0)
                    return 0;
            } break;
            case QUICLY_FRAME_TYPE_MAX_DATA: {
                quicly_max_data_frame_t frame;
                if ((ret = quicly_decode_max_data_frame(&src, end, &frame)) != 0)
                    return 0;
            } break;
            case QUICLY_FRAME_TYPE_MAX_STREAM_DATA: {
                quicly_max_stream_data_frame_t frame;
                if ((ret = quicly_decode_max_stream_data_frame(&src, end, &frame)) != 0)
                    return 0;
            } break;
            case QUICLY_FRAME_TYPE_MAX_STREAM_ID: {
                quicly_max_stream_id_frame_t frame;
                if ((ret = quicly_decode_max_stream_id_frame(&src, end, &frame)) != 0)
                    return 0;
            } break;
            case QUICLY_FRAME_TYPE_STREAM_BLOCKED: {
                quicly_stream_blocked_frame_t frame;
                if ((ret = quicly_decode_stream_blocked_frame(&src, end, &frame)) != 0)
                    return 0;
            } break;
            case QUICLY_FRAME_TYPE_STOP_SENDING: {
                quicly_stop_sending_frame_t frame;
                if ((ret = quicly_decode_stop_sending_frame(&src, end, &frame)) != 0)
                    return 0;
            } break;
	    };
	}
	return 0;
}
