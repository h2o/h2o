#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/frame.h"

void __sanitizer_cov_trace_pc(void)
{
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	int ret;
	quicly_context_t ctx;
	quicly_decoded_packet_t p;

	ctx = quicly_spec_context;

	ret = quicly_decode_packet(&ctx, &p, Data, Size);

	if (ret != Size)
		return 0;
	const uint8_t *src = p.octets.base, *end = src + p.octets.len;
	if (p.octets.len == 0)
		return 0;

        uint8_t type_flags = *src++;
        if ((type_flags & ~QUICLY_FRAME_TYPE_STREAM_BITS) == QUICLY_FRAME_TYPE_STREAM_BASE) {
            quicly_stream_frame_t frame;
            if ((ret = quicly_decode_stream_frame(type_flags, &src, end, &frame)) != 0)
                return 0;
	} else {
            switch (type_flags) {
        	case QUICLY_FRAME_TYPE_TRANSPORT_CLOSE: {
            		quicly_transport_close_frame_t frame;
            		if ((ret = quicly_decode_transport_close_frame(&src, end, &frame)) != 0)
                		return 0;
        	} break;
        	case QUICLY_FRAME_TYPE_APPLICATION_CLOSE: {
            		quicly_application_close_frame_t frame;
            		if ((ret = quicly_decode_application_close_frame(&src, end, &frame)) != 0)
                		return 0;
        	} break;
        	case QUICLY_FRAME_TYPE_ACK:
        	case QUICLY_FRAME_TYPE_ACK_ECN: {
        		quicly_ack_frame_t frame;
            		if ((ret = quicly_decode_ack_frame(&src, end, &frame, type_flags == QUICLY_FRAME_TYPE_ACK_ECN)) != 0)
               			return 0;
        	} break;
        	case QUICLY_FRAME_TYPE_CRYPTO:
            		quicly_stream_frame_t frame;
            		if ((ret = quicly_decode_crypto_frame(&src, end, &frame)) != 0)
                		return 0;
            	break;
                case QUICLY_FRAME_TYPE_RESET_STREAM: {
                    quicly_reset_stream_frame_t frame;
                    if ((ret = quicly_decode_reset_stream_frame(&src, end, &frame)) != 0)
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
                case QUICLY_FRAME_TYPE_MAX_STREAMS_BIDI:
                case QUICLY_FRAME_TYPE_MAX_STREAMS_UNI: {
                    quicly_max_streams_frame_t frame;
                    if ((ret = quicly_decode_max_streams_frame(&src, end, &frame)) != 0)
                        return 0;
                } break;
                case QUICLY_FRAME_TYPE_PING:
                    ret = 0;
                    break;
                case QUICLY_FRAME_TYPE_DATA_BLOCKED: {
                    quicly_data_blocked_frame_t frame;
                    if ((ret = quicly_decode_data_blocked_frame(&src, end, &frame)) != 0)
                        return 0;
                } break;
                case QUICLY_FRAME_TYPE_STREAM_DATA_BLOCKED: {
                    quicly_stream_data_blocked_frame_t frame;
                    if ((ret = quicly_decode_stream_data_blocked_frame(&src, end, &frame)) != 0)
                        return 0;
                } break;
                case QUICLY_FRAME_TYPE_STREAMS_BLOCKED_BIDI:
                case QUICLY_FRAME_TYPE_STREAMS_BLOCKED_UNI: {
                    quicly_streams_blocked_frame_t frame;
                    if ((ret = quicly_decode_streams_blocked_frame(&src, end, &frame)) != 0)
                        return 0;
                } break;
                case QUICLY_FRAME_TYPE_NEW_CONNECTION_ID: {
                    quicly_new_connection_id_frame_t frame;
                    if ((ret = quicly_decode_new_connection_id_frame(&src, end, &frame)) != 0)
                        return 0;
                } break;
                case QUICLY_FRAME_TYPE_STOP_SENDING: {
                    quicly_stop_sending_frame_t frame;
                    if ((ret = quicly_decode_stop_sending_frame(&src, end, &frame)) != 0)
                        return 0;
                } break;
                case QUICLY_FRAME_TYPE_PATH_CHALLENGE: {
                    quicly_path_challenge_frame_t frame;
                    if ((ret = quicly_decode_path_challenge_frame(&src, end, &frame)) != 0)
                        return 0;
                } break;
                case QUICLY_FRAME_TYPE_NEW_TOKEN: {
                    quicly_new_token_frame_t frame;
                    if ((ret = quicly_decode_new_token_frame(&src, end, &frame)) != 0)
                        return 0;
                } break;
	    };
	}
	return 0;
}
