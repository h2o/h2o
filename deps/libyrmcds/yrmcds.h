/** @file yrmcds.h
 * libyrmcds public API.
 * (C) 2013-2016 Cybozu.
 */

#pragma once

#ifndef YRMCDS_H_INCLUDED
#define YRMCDS_H_INCLUDED

/// Library version string such as "1.3.0".
#define LIBYRMCDS_VERSION        "1.3.0"

/// Library version number such as 10201.
#define LIBYRMCDS_VERSION_NUMBER  10300

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

    /* for text mode */
    int      text_mode;     ///< text mode flag.
    uint32_t rserial;       ///< serial emulation.
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

    YRMCDS_STATUS_OTHER = 0xffff,    ///< unknown error in text protocol.
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

    YRMCDS_CMD_KEYS       = '\x50',

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
    YRMCDS_COMPRESS_FAILED,   ///< LZ4 compression failed.
    YRMCDS_PROTOCOL_ERROR,    ///< received malformed packet.
    YRMCDS_NOT_IMPLEMENTED,   ///< the function is not available.
    YRMCDS_IN_BINARY,         ///< connection is fixed for binary protocol.
    YRMCDS_BAD_KEY,           ///< bad key.
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
 * Shutdown the receiving end of the socket.
 * @param  c     A pointer to ::yrmcds.
 * @return 0 if \p c is valid.  Other values indicate an error.
 *
 * This function simply calls \p shutdown system call with \p SHUT_RD .
 * This can be used to interrupt a thread waiting in ::yrmcds_recv.
 *
 * Note that interrupted ::yrmcds_recv will return ::YRMCDS_DISCONNECTED.
 *
 * \see https://github.com/cybozu/libyrmcds/issues/8
 */
yrmcds_error yrmcds_shutdown(yrmcds* c);


/**
 * Turn on text protocol mode.
 * @param  c  A pointer to ::yrmcds.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function puts the connection into text protocol mode.
 * \p c should be a newly connected object; if any (binary) request
 * has been sent, this function will return an error.
 *
 * Text protocol mode has overheads and limitations; most notably,
 * \p quiet option for command sending functions cannot be enabled.
 */
yrmcds_error yrmcds_text_mode(yrmcds* c);


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
 * If the library is built without LZ4, this function always return
 * ::YRMCDS_NOT_IMPLEMENTED.
 *
 * Note that ::YRMCDS_FLAG_COMPRESS bit in the flags of compressed objects
 * will be used by the library iff the compression is enabled.
 */
yrmcds_error yrmcds_set_compression(yrmcds* c, size_t threshold);


/**
 * Return the underlying socket in ::yrmcds.
 * @param  c     A pointer to ::yrmcds.
 * @return       A UNIX file descriptor of a socket.
 */
int yrmcds_fileno(yrmcds* c);


/**
 * Set timeout seconds for send/recv operations.
 * @param  c        A pointer to ::yrmcds.
 * @param  timeout  Seconds before network operations time out.
 * @return 0 if arguments are valid.  Other values indicate an error.
 */
yrmcds_error yrmcds_set_timeout(yrmcds* c, int timeout);


/**
 * Receives a response packet.
 * @param  c     A pointer to ::yrmcds.
 * @param  r     A pointer to ::yrmcds_response.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function receives a response packet.  If no response is available,
 * the function will be blocked.  For each \p c, only one thread can use
 * this function, though command sending functions can be used in parallel.
 *
 * The response data stored in \p r keep valid until the next call of this
 * function or until ::yrmcds_close is called.  \p r can be reused for the
 * next call of ::yrmcds_recv.
 *
 * This will return ::YRMCDS_DISCONNECTED when the socket is closed or
 * ::yrmcds_shutdown is called from another thread.
 */
yrmcds_error yrmcds_recv(yrmcds* c, yrmcds_response* r);


/**
 * Send Noop command.
 * @param  c       A pointer to ::yrmcds.
 * @param  serial  A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Noop command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_noop(yrmcds* c, uint32_t* serial);


/**
 * Send Get/GetQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  quiet     0 to send Get, other values to send GetQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Get/GetQ command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_get(yrmcds* c, const char* key, size_t key_len,
                        int quiet, uint32_t* serial);


/**
 * Send GetK/GetKQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  quiet     0 to send GetK, other values to send GetKQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends GetK/GetKQ command to the server.
 * Unlike yrmcds_get(), the response to this request brings the key.
 *
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_getk(yrmcds* c, const char* key, size_t key_len,
                         int quiet, uint32_t* serial);


/**
 * Send GaT/GaTQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  expire    Expiration time.  0 disables expiration.
 * @param  quiet     0 to send GaT, other values to send GaTQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends GaT/GaTQ (get and touch) command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_get_touch(yrmcds* c, const char* key, size_t key_len,
                              uint32_t expire, int quiet, uint32_t* serial);


/**
 * Send GaTK/GaTKQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  expire    Expiration time.  0 disables expiration.
 * @param  quiet     0 to send GaTK, other values to send GaTKQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends GaTK/GaTKQ (get and touch) command to the server.
 * Unlike yrmcds_get_touch(), the response to this request brings the key.
 *
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_getk_touch(yrmcds* c, const char* key, size_t key_len,
                               uint32_t expire, int quiet, uint32_t* serial);


/**
 * Send LaG/LaGQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  quiet     0 to send LaG, other values to send LaGQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends LaG/LaGQ command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_lock_get(yrmcds* c, const char* key, size_t key_len,
                             int quiet, uint32_t* serial);


/**
 * Send LaGK/LaGKQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  quiet     0 to send LaGK, other values to send LaGKQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends LaGK/LaGKQ command to the server.
 * Unlike yrmcds_lock_get(), the response to this request brings the key.
 *
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_lock_getk(yrmcds* c, const char* key, size_t key_len,
                              int quiet, uint32_t* serial);


/**
 * Send Touch command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  expire    Expiration time.  0 disables expiration.
 * @param  quiet     Reserved for future enhancement.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Touch command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_touch(yrmcds* c, const char* key, size_t key_len,
                          uint32_t expire, int quiet, uint32_t* serial);


/**
 * Send Set/SetQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  data      Data to be stored.
 * @param  data_len  Length of \p data.
 * @param  flags     Flags stored along with the data.
 * @param  expire    Expiration time.  0 disables expiration.
 * @param  cas       Try compare-and-swap.  0 disables CAS.
 * @param  quiet     0 to send Set, other values to send SetQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Set/SetQ command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_set(yrmcds* c, const char* key, size_t key_len,
                        const char* data, size_t data_len,
                        uint32_t flags, uint32_t expire, uint64_t cas,
                        int quiet, uint32_t* serial);


/**
 * Send Replace/ReplaceQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  data      Data to be stored.
 * @param  data_len  Length of \p data.
 * @param  flags     Flags stored along with the data.
 * @param  expire    Expiration time.  0 disables expiration.
 * @param  cas       Try compare-and-swap.  0 disables CAS.
 * @param  quiet     0 to send Replace, other values to send ReplaceQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Replace/ReplaceQ command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_replace(yrmcds* c, const char* key, size_t key_len,
                            const char* data, size_t data_len,
                            uint32_t flags, uint32_t expire, uint64_t cas,
                            int quiet, uint32_t* serial);


/**
 * Send Add/AddQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  data      Data to be stored.
 * @param  data_len  Length of \p data.
 * @param  flags     Flags stored along with the data.
 * @param  expire    Expiration time.  0 disables expiration.
 * @param  cas       Try compare-and-swap.  0 disables CAS.
 * @param  quiet     0 to send Add, other values to send AddQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Add/AddQ command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_add(yrmcds* c, const char* key, size_t key_len,
                        const char* data, size_t data_len,
                        uint32_t flags, uint32_t expire, uint64_t cas,
                        int quiet, uint32_t* serial);


/**
 * Send RaU/RaUQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  data      Data to be stored.
 * @param  data_len  Length of \p data.
 * @param  flags     Flags stored along with the data.
 * @param  expire    Expiration time.  0 disables expiration.
 * @param  quiet     0 to send RaU, other values to send RaUQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends RaU/RaUQ (replace and unlock) command to the server.
 * The command will fail unless the object is locked by the same session.
 *
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_replace_unlock(yrmcds* c, const char* key, size_t key_len,
                                   const char* data, size_t data_len,
                                   uint32_t flags, uint32_t expire,
                                   int quiet, uint32_t* serial);


/**
 * Send Increment/IncrementQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  value     Amount to add.
 * @param  quiet     0 to send Increment, other values to send IncrementQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Increment/IncrementQ command to the server.
 * If \p key is not found, the command will fail.
 *
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_incr(yrmcds* c, const char* key, size_t key_len,
                         uint64_t value, int quiet, uint32_t* serial);


/**
 * Send Increment/IncrementQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  value     Amount to add.
 * @param  initial   Initial value used when \p key does not exist.
 * @param  expire    Expiration time.  0 disables expiration.
 * @param  quiet     0 to send Increment, other values to send IncrementQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Increment/IncrementQ command to the server.
 * Unlike yrmcds_incr(), this function creates a new object with
 * \p initial and \p expire when \p key is not found.
 *
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_incr2(yrmcds* c, const char* key, size_t key_len,
                          uint64_t value, uint64_t initial, uint32_t expire,
                          int quiet, uint32_t* serial);


/**
 * Send Decrement/DecrementQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  value     Amount to add.
 * @param  quiet     0 to send Decrement, other values to send DecrementQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Decrement/DecrementQ command to the server.
 * If \p key is not found, the command will fail.
 *
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_decr(yrmcds* c, const char* key, size_t key_len,
                         uint64_t value, int quiet, uint32_t* serial);


/**
 * Send Decrement/DecrementQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  value     Amount to add.
 * @param  initial   Initial value used when \p key does not exist.
 * @param  expire    Expiration time.  0 disables expiration.
 * @param  quiet     0 to send Decrement, other values to send DecrementQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Decrement/DecrementQ command to the server.
 * Unlike yrmcds_decr(), this function creates a new object with
 * \p initial and \p expire when \p key is not found.
 *
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_decr2(yrmcds* c, const char* key, size_t key_len,
                          uint64_t value, uint64_t initial, uint32_t expire,
                          int quiet, uint32_t* serial);


/**
 * Send Append/AppendQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  data      Data.
 * @param  data_len  Length of \p data.
 * @param  quiet     0 to send Append, other values to send AppendQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Append/AppendQ command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 *
 * \b WARNING: if compression is enabled, this may collapse the data!
 */
yrmcds_error yrmcds_append(yrmcds* c, const char* key, size_t key_len,
                           const char* data, size_t data_len,
                           int quiet, uint32_t* serial);


/**
 * Send Prepend/PrependQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  data      Data.
 * @param  data_len  Length of \p data.
 * @param  quiet     0 to send Prepend, other values to send PrependQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Prepend/PrependQ command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 *
 * \b WARNING: if compression is enabled, this may collapse the data!
 */
yrmcds_error yrmcds_prepend(yrmcds* c, const char* key, size_t key_len,
                            const char* data, size_t data_len,
                            int quiet, uint32_t* serial);


/**
 * Send Delete/DeleteQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  quiet     0 to send Delete, other values to send DeleteQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Delete/DeleteQ command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_remove(yrmcds* c, const char* key, size_t key_len,
                           int quiet, uint32_t* serial);


/**
 * Send Lock/LockQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  quiet     0 to send Lock, other values to send LockQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Lock/LockQ command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_lock(yrmcds* c, const char* key, size_t key_len,
                         int quiet, uint32_t* serial);


/**
 * Send Unlock/UnlockQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  key       Key data.
 * @param  key_len   Length of \p key.
 * @param  quiet     0 to send Unlock, other values to send UnlockQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Unlock/UnlockQ command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_unlock(yrmcds* c, const char* key, size_t key_len,
                           int quiet, uint32_t* serial);


/**
 * Send UnlockAll/UnlockAllQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  quiet     0 to send UnlockAll, other values to send UnlockAllQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends UnlockAll/UnlockAllQ command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_unlockall(yrmcds* c, int quiet, uint32_t* serial);


/**
 * Send Flush/FlushQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  delay     delay seconds before flush.
 * @param  quiet     0 to send Flush, other values to send FlushQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Flush/FlushQ command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error yrmcds_flush(yrmcds* c, uint32_t delay,
                          int quiet, uint32_t* serial);

/**
 * Send Stat command to obtain general statistics.
 * @param  c         A pointer to ::yrmcds.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 */
yrmcds_error yrmcds_stat_general(yrmcds* c, uint32_t* serial);


/**
 * Send Stat command to obtain setting statistics.
 * @param  c         A pointer to ::yrmcds.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 */
yrmcds_error yrmcds_stat_settings(yrmcds* c, uint32_t* serial);


/**
 * Send Stat command to obtain item statistics.
 * @param  c         A pointer to ::yrmcds.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 */
yrmcds_error yrmcds_stat_items(yrmcds* c, uint32_t* serial);


/**
 * Send Stat command to obtain size statistics.
 * @param  c         A pointer to ::yrmcds.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 */
yrmcds_error yrmcds_stat_sizes(yrmcds* c, uint32_t* serial);


/**
 * Send Keys command to list all keys matching the given prefix.
 * To retrieve all keys, pass \p NULL and 0 as \p prefix and \p prefix_len.
 * @param  c          A pointer to ::yrmcds.
 * @param  prefix     Prefix data.
 * @param  prefix_len Length of \p prefix.
 * @param  serial     A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 */
yrmcds_error yrmcds_keys(yrmcds* c, const char* prefix, size_t prefix_len,
                         uint32_t* serial);


/**
 * Send Version command.
 * @param  c         A pointer to ::yrmcds.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 */
yrmcds_error yrmcds_version(yrmcds* c, uint32_t* serial);


/**
 * Send Quit/QuitQ command.
 * @param  c         A pointer to ::yrmcds.
 * @param  quiet     0 to send Quit, other values to send QuitQ.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 */
yrmcds_error yrmcds_quit(yrmcds* c, int quiet, uint32_t* serial);


/**
 * @}
 * @mainpage A memcached/yrmcds client library for C.
 *
 * - \ref yrmcds_functions
 * - \ref yrmcds_cnt_functions
 */

/**
 * Data structure to store the reference to a statistic data for the counter extension.
 */
typedef struct {
    const char* name;           ///< the name of a statistic item
    size_t name_length;         ///< the length of \p name
    const char* value;          ///< the ASCII text information
    size_t value_length;        ///< the length of \p value
} yrmcds_cnt_stat;

/**
 * Data structure to store statistics for the counter extension.
 */
typedef struct {
    yrmcds_cnt_stat* records;   ///< the array of the statistic information
    size_t count;               ///< the number of statistics
    size_t capacity;            ///< the maximum number of records that \p records can hold.
} yrmcds_cnt_statistics;

/**
 * Data structure of a connection to yrmcds counter server.
 */
typedef struct {
    pthread_mutex_t lock;        ///< guard lock to serialize sends.
    yrmcds_cnt_statistics stats; ///< the result of `stats` command.
    char* recvbuf;               ///< received data buffer.
    size_t capacity;             ///< buffer capacity.
    size_t used;                 ///< used bytes.
    size_t last_size;            ///< size of the last response.
    int sock;                    ///< the socket file descriptor.
    int invalid;                 ///< invalid flag.
    uint32_t serial;             ///< last issued serial number.
} yrmcds_cnt;

/**
 * Server status codes for the counter extension.
 */
typedef enum {
    YRMCDS_CNT_STATUS_OK                     = 0x00,
    YRMCDS_CNT_STATUS_NOT_FOUND              = 0x01,
    YRMCDS_CNT_STATUS_INVALID                = 0x04,
    YRMCDS_CNT_STATUS_RESOURCE_NOT_AVAILABLE = 0x21,
    YRMCDS_CNT_STATUS_NOT_ACQUIRED           = 0x22,
    YRMCDS_CNT_STATUS_UNKNOWN_COMMAND        = 0x81,
    YRMCDS_CNT_STATUS_OUT_OF_MEMORY          = 0x82,
} yrmcds_cnt_status;

/**
 * Binary commands for the counter extension.
 */
typedef enum {
    YRMCDS_CNT_CMD_NOOP    = 0x00,
    YRMCDS_CNT_CMD_GET     = 0x01,
    YRMCDS_CNT_CMD_ACQUIRE = 0x02,
    YRMCDS_CNT_CMD_RELEASE = 0x03,
    YRMCDS_CNT_CMD_STATS   = 0x10,
    YRMCDS_CNT_CMD_DUMP    = 0x11,
} yrmcds_cnt_command;

/**
 * Data structure to store a response packet for the counter extension.
 */
typedef struct {
    yrmcds_cnt_statistics* stats; ///< the result of `stats` command.
    const char* body;             ///< the pointer to the response body.
    size_t body_length;           ///< the body length of the response packet.
    const char* name;             ///< the name of the semaphore (only for Dump command).
    size_t name_length;           ///< the length of \p name (only for Dump command).
    uint32_t serial;              ///< serial number of the corresponding request.
    uint32_t resources;           ///< the number of acquired resources.
    uint32_t current_consumption; ///< the current consumption of resources.
    uint32_t max_consumption;     ///< maximum consumption (only for Dump command).
    uint8_t status;               ///< the response status.
    uint8_t command;              ///< the request command.
} yrmcds_cnt_response;

/**
 * @defgroup yrmcds_cnt_functions  Public functions for the counter extension
 * @{
 */

/**
 * Connecct to a yrmcds server.
 * @param  c     A pointer to ::yrmcds_cnt.
 * @param  node  The server name.
 * @param  port  TCP port number of the server (normally 11215).
 * @return 0 if connected successfully.  Other values indicate an error.
 *
 * This function connects to a yrmcds server and initializes
 * \p c.  TCP_NODELAY flag will be set for the returned socket.
 */
yrmcds_error
yrmcds_cnt_connect(yrmcds_cnt* c, const char* node, uint16_t port);

/**
 * Close the connection.
 * @param  c     A pointer to ::yrmcds_cnt.
 * @return 0 if \p c is valid.  Other values indicate an error.
 *
 * This function closes the connection and frees buffers in \p c.
 */
yrmcds_error
yrmcds_cnt_close(yrmcds_cnt* c);

/**
 * Shutdown the receiving end of the socket.
 * @param  c     A pointer to ::yrmcds_cnt.
 * @return 0 if \p c is valid.  Other values indicate an error.
 *
 * This function simply calls \p shutdown system call with \p SHUT_RD .
 * This can be used to interrupt a thread waiting in ::yrmcds_cnt_recv.
 *
 * Note that interrupted ::yrmcds_cnt_recv will return ::YRMCDS_DISCONNECTED.
 *
 * \see https://github.com/cybozu/libyrmcds/issues/8
 */
yrmcds_error
yrmcds_cnt_shutdown(yrmcds_cnt* c);

/**
 * Return the underlying socket in ::yrmcds_cnt.
 * @param  c     A pointer to ::yrmcds_cnt.
 * @return       A UNIX file descriptor of a socket.
 */
int
yrmcds_cnt_fileno(yrmcds_cnt* c);

/**
 * Set timeout seconds for send/recv operations.
 * @param  c        A pointer to ::yrmcds_cnt.
 * @param  timeout  Seconds before network operations time out.
 * @return 0 if arguments are valid.  Other values indicate an error.
 */
yrmcds_error
yrmcds_cnt_set_timeout(yrmcds_cnt* c, int timeout);

/**
 * Receives a response packet.
 * @param  c     A pointer to ::yrmcds_cnt.
 * @param  r     A pointer to ::yrmcds_cnt_response.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function receives a response packet.  If no response is available,
 * the function will be blocked.  For each \p c, only one thread can use
 * this function, though command sending functions can be used in parallel.
 *
 * The response data stored in \p r keep valid until the next call of this
 * function or until yrmcds_cnt_close() is called.  \p r can be reused for the
 * next call of yrmcds_cnt_recv().
 */
yrmcds_error
yrmcds_cnt_recv(yrmcds_cnt* c, yrmcds_cnt_response* r);

/**
 * Send Noop command.
 * @param  c       A pointer to ::yrmcds_cnt.
 * @param  serial  A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Noop command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error
yrmcds_cnt_noop(yrmcds_cnt* c, uint32_t* serial);

/**
 * Send Get command.
 * @param  c         A pointer to ::yrmcds_cnt.
 * @param  name      Name.
 * @param  name_len  Length of \p name.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Get command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error
yrmcds_cnt_get(yrmcds_cnt* c,
               const char* name, size_t name_len, uint32_t* serial);

/**
 * Send Acquire command.
 * @param  c         A pointer to ::yrmcds_cnt.
 * @param  name      Name.
 * @param  name_len  Length of \p name.
 * @param  resources The number of resources to acquire.
 * @param  maximum   The maximum number of resources.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Acquire command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error
yrmcds_cnt_acquire(yrmcds_cnt* c, const char* name, size_t name_len,
                   uint32_t resources, uint32_t maximum, uint32_t* serial);

/**
 * Send Release command.
 * @param  c         A pointer to ::yrmcds_cnt.
 * @param  name      Name.
 * @param  name_len  Length of \p name.
 * @param  resources The number of resources to release.
 * @param  serial    A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Release command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error
yrmcds_cnt_release(yrmcds_cnt* c, const char* name, size_t name_len,
                   uint32_t resources, uint32_t* serial);

/**
 * Send Stats command.
 * @param  c       A pointer to ::yrmcds_cnt.
 * @param  serial  A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Stats command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error
yrmcds_cnt_stats(yrmcds_cnt* c, uint32_t* serial);

/**
 * Send Dump command.
 * @param  c       A pointer to ::yrmcds_cnt.
 * @param  serial  A pointer to \p uint32_t, or \p NULL.
 * @return 0 if succeeded.  Other values indicate an error.
 *
 * This function sends Dump command to the server.
 * If \p serial is not \p NULL, the serial number of the request will be
 * stored if the command was sent successfully.
 */
yrmcds_error
yrmcds_cnt_dump(yrmcds_cnt* c, uint32_t* serial);

/**
 * @}
 */

#ifdef __cplusplus
} // extern "C"
#endif

#endif // YRMCDS_H_INCLUDED
