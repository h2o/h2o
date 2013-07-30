/** @file yrmcds.h
 * libyrmcds public API.
 * (C) 2013 Cybozu.
 */

#pragma once

#ifndef YRMCDS_H_INCLUDED
#define YRMCDS_H_INCLUDED

#define LIBYRMCDS_VERSION        "1.0.0"
#define LIBYRMCDS_VERSION_NUMBER  10000

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Data structure of a connection to memcached/yrmcds server.
 */
typedef struct {
    int sock;               ///< the socket file descriptor.

    /* for sending */
    pthread_mutex_t lock;   ///< guard lock to serialize sends.
    uint32_t serial;        ///< last issued serial number.
    size_t compress_size;   ///< threshold data size for LZ4 compression.

    /* for receiving */
    char*  recvbuf;         ///< received data buffer.
    size_t capacity;        ///< buffer capacity
    size_t used;            ///< used bytes.
    size_t last_size;       ///< size of the last response.
    char*  decompressed;    ///< decompressed data.
    int    invalid;         ///< invalid flag.
} yrmcds;


/**
 * Server status codes.
 */
typedef enum {
    YRMCDS_STATUS_OK = 0,
    YRMCDS_STATUS_NOTFOUND = 0x0001,
    YRMCDS_STATUS_EXISTS = 0x0002,
    YRMCDS_STATUS_TOOLARGEVALUE = 0x0003,
    YRMCDS_STATUS_INVALID = 0x0004,
    YRMCDS_STATUS_NOTSTORED = 0x0005,
    YRMCDS_STATUS_NONNUMERIC = 0x0006,
    YRMCDS_STATUS_LOCKED = 0x0010,
    YRMCDS_STATUS_NOTLOCKED = 0x0011,
    YRMCDS_STATUS_UNKNOWNCOMMAND = 0x0081,
    YRMCDS_STATUS_OUTOFMEMORY = 0x0082,
} yrmcds_status;


/**
 * Binary commands.
 */
typedef enum {
    YRMCDS_CMD_GET        = '\x00',
    YRMCDS_CMD_SET        = '\x01',
    YRMCDS_CMD_ADD        = '\x02',
    YRMCDS_CMD_REPLACE    = '\x03',
    YRMCDS_CMD_DELETE     = '\x04',
    YRMCDS_CMD_INCREMENT  = '\x05',
    YRMCDS_CMD_DECREMENT  = '\x06',
    YRMCDS_CMD_QUIT       = '\x07',
    YRMCDS_CMD_FLUSH      = '\x08',
    YRMCDS_CMD_GETQ       = '\x09',
    YRMCDS_CMD_NOOP       = '\x0a',
    YRMCDS_CMD_VERSION    = '\x0b',
    YRMCDS_CMD_GETK       = '\x0c',
    YRMCDS_CMD_GETKQ      = '\x0d',
    YRMCDS_CMD_APPEND     = '\x0e',
    YRMCDS_CMD_PREPEND    = '\x0f',
    YRMCDS_CMD_STAT       = '\x10',
    YRMCDS_CMD_SETQ       = '\x11',
    YRMCDS_CMD_ADDQ       = '\x12',
    YRMCDS_CMD_REPLACEQ   = '\x13',
    YRMCDS_CMD_DELETEQ    = '\x14',
    YRMCDS_CMD_INCREMENTQ = '\x15',
    YRMCDS_CMD_DECREMENTQ = '\x16',
    YRMCDS_CMD_QUITQ      = '\x17',
    YRMCDS_CMD_FLUSHQ     = '\x18',
    YRMCDS_CMD_APPENDQ    = '\x19',
    YRMCDS_CMD_PREPENDQ   = '\x1a',
    YRMCDS_CMD_TOUCH      = '\x1c',
    YRMCDS_CMD_GAT        = '\x1d',
    YRMCDS_CMD_GATQ       = '\x1e',
    YRMCDS_CMD_GATK       = '\x23',
    YRMCDS_CMD_GATKQ      = '\x24',

    YRMCDS_CMD_LOCK       = '\x40',
    YRMCDS_CMD_LOCKQ      = '\x41',
    YRMCDS_CMD_UNLOCK     = '\x42',
    YRMCDS_CMD_UNLOCKQ    = '\x43',
    YRMCDS_CMD_UNLOCKALL  = '\x44',
    YRMCDS_CMD_UNLOCKALLQ = '\x45',
    YRMCDS_CMD_LAG        = '\x46',
    YRMCDS_CMD_LAGQ       = '\x47',
    YRMCDS_CMD_LAGK       = '\x48',
    YRMCDS_CMD_LAGKQ      = '\x49',
    YRMCDS_CMD_RAU        = '\x4a',
    YRMCDS_CMD_RAUQ       = '\x4b',

    YRMCDS_CMD_BOTTOM     // place this at the bottom.
} yrmcds_command;


/**
 * Data structure to store a response packet.
 */
typedef struct {
    uint32_t serial;         ///< serial number of the corresponding request.
    size_t length;           ///< the length of the response packet.
    yrmcds_status status;    ///< the response status.
    yrmcds_command command;  ///< the request command.
    uint64_t cas_unique;     ///< CAS unique value.
    uint32_t flags;          ///< The object's flags.
    const char* key;         ///< Returned key for GetK/GaTK/LaGK.
    size_t key_len;          ///< The length of \p key.
    const char* data;        ///< Returned data for Get commands.
    size_t data_len;         ///< The length of \p data.
    uint64_t value;          ///< The new value after Increment or Decrement.
} yrmcds_response;


/**
 * Library error numbers.
 */
typedef enum {
    YRMCDS_OK = 0,
    YRMCDS_SYSTEM_ERROR,      ///< check \p errno for details.
    YRMCDS_BAD_ARGUMENT,      ///< bad arguments.
    YRMCDS_NOT_RESOLVED,      ///< host name cannot be resolved.
    YRMCDS_TIMEOUT,           ///< time out for some network operations.
    YRMCDS_DISCONNECTED,      ///< connection was reset unexpectedly.
    YRMCDS_OUT_OF_MEMORY,     ///< malloc/realloc failed.
    YRMCDS_PROTOCOL_ERROR,    ///< received malformed packet.
} yrmcds_error;


/**
 * Reserved flag bits.
 */
typedef enum {
    YRMCDS_FLAG_COMPRESS = 1 << 30,  ///< transparent LZ4 compression.
} yrmcds_flags;


/**
 * @defgroup yrmcds_functions  Public functions
 * @{
 */

/**
 * Return a string to describe a library error.
 * @param  e   An error number returned from a library function.
 * @return     A pointer to a constant string.
 */
const char* yrmcds_strerror(yrmcds_error e);


/**
 * Connecct to a memcached/yrmcds server.
 * @param  c     A pointer to ::yrmcds.
 * @param  node  The server name.
 * @param  port  TCP port number of the server (normally 11211).
 * @return 0 if connected successfully.  Other values indicate an error.
 *
 * This function connects to a memcached/yrmcds server and initializes
 * \p c.  TCP_NODELAY flag will be set for the returned socket.
 */
yrmcds_error yrmcds_connect(yrmcds* c, const char* node, uint16_t port);


/**
 * Close the connection.
 * @param  c     A pointer to ::yrmcds.
 * @return 0 if \p c is valid.  Other values indicate an error.
 *
 * This function closes the connection and frees buffers in \p c.
 */
yrmcds_error yrmcds_close(yrmcds* c);


/**
 * Enable/disable (de)compression for large objects.
 * @param  c     A pointer to ::yrmcds.
 * @param  threshold  The threshold for compression.
 * @return 0 if arguments are valid.  Other values indicate an error.
 *
 * This function enables transparent compression using LZ4 if \p threshold
 * is greater than 0.  If \p threshold is 0, then compression is disabled.
 *
 * The compression is disabled by default.
 *
 * Note that ::YRMCDS_FLAG_COMPRESS bit in the flags of compressed objects
 * will be used by the library iff the compression is enabled.
 */
yrmcds_error yrmcds_set_compression(yrmcds* c, size_t threshold);


/**
 * Receives a response packet.
 * @param  c     A pointer to ::yrmcds.
 * @param  r     A pointer to ::yrmcds_response.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function receives a response packet.  If no response is available,
 * the function will be blocked.  This function can be used in parallel
 * with sending command functions, though this function itself must be
 * called by only one thread.
 *
 * The response data stored in \p r keep valid until the next call of this
 * function or until yrmcds_close() is called.  \p r can be reused for the
 * next call of yrmcds_recv().
 */
yrmcds_error yrmcds_recv(yrmcds* c, yrmcds_response* r);


/**
 * Send Noop command.
 * @param  c      A pointer to ::yrmcds.
 * @param  serial  A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Noop command to the server.
 * if \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_noop(yrmcds* c, uint32_t* serial);


/**
 * @}
 * @mainpage A memcached/yrmcds client library for C.
 *
 * \ref yrmcds_functions
 */

#ifdef __cplusplus
} // extern "C"
#endif

#endif // YRMCDS_H_INCLUDED
