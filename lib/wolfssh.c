/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifdef USE_WOLFSSH

#include <limits.h>

#include <wolfssh/ssh.h>
#include <wolfssh/wolfsftp.h>
#include "urldata.h"
#include "connect.h"
#include "sendf.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

static CURLcode wssh_connect(struct connectdata *conn, bool *done);
static CURLcode wssh_multi_statemach(struct connectdata *conn, bool *done);
static CURLcode wssh_do(struct connectdata *conn, bool *done);
static CURLcode wscp_done(struct connectdata *conn,
                         CURLcode, bool premature);
static CURLcode wscp_doing(struct connectdata *conn,
                          bool *dophase_done);
static CURLcode wscp_disconnect(struct connectdata *conn,
                                bool dead_connection);
static CURLcode wsftp_done(struct connectdata *conn,
                          CURLcode, bool premature);
static CURLcode wsftp_doing(struct connectdata *conn,
                           bool *dophase_done);
static CURLcode wsftp_disconnect(struct connectdata *conn, bool dead);

static int wssh_getsock(struct connectdata *conn,
                       curl_socket_t *sock, /* points to numsocks number
                                               of sockets */
                       int numsocks);

static int wssh_perform_getsock(const struct connectdata *conn,
                               curl_socket_t *sock, /* points to numsocks
                                                       number of sockets */
                               int numsocks);

static CURLcode wssh_setup_connection(struct connectdata *conn);

/*
 * SCP protocol handler.
 */

const struct Curl_handler Curl_handler_scp = {
  "SCP",                                /* scheme */
  wssh_setup_connection,                /* setup_connection */
  wssh_do,                              /* do_it */
  wscp_done,                            /* done */
  ZERO_NULL,                            /* do_more */
  wssh_connect,                         /* connect_it */
  wssh_multi_statemach,                 /* connecting */
  wscp_doing,                           /* doing */
  wssh_getsock,                         /* proto_getsock */
  wssh_getsock,                         /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  wssh_perform_getsock,                 /* perform_getsock */
  wscp_disconnect,                      /* disconnect */
  ZERO_NULL,                            /* readwrite */
  ZERO_NULL,                            /* connection_check */
  PORT_SSH,                             /* defport */
  CURLPROTO_SCP,                        /* protocol */
  PROTOPT_DIRLOCK | PROTOPT_CLOSEACTION
  | PROTOPT_NOURLQUERY                  /* flags */
};


/*
 * SFTP protocol handler.
 */

const struct Curl_handler Curl_handler_sftp = {
  "SFTP",                               /* scheme */
  wssh_setup_connection,                /* setup_connection */
  wssh_do,                              /* do_it */
  wsftp_done,                           /* done */
  ZERO_NULL,                            /* do_more */
  wssh_connect,                         /* connect_it */
  wssh_multi_statemach,                 /* connecting */
  wsftp_doing,                          /* doing */
  wssh_getsock,                         /* proto_getsock */
  wssh_getsock,                         /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  wssh_perform_getsock,                 /* perform_getsock */
  wsftp_disconnect,                     /* disconnect */
  ZERO_NULL,                            /* readwrite */
  ZERO_NULL,                            /* connection_check */
  PORT_SSH,                             /* defport */
  CURLPROTO_SFTP,                       /* protocol */
  PROTOPT_DIRLOCK | PROTOPT_CLOSEACTION
  | PROTOPT_NOURLQUERY                  /* flags */
};

/*
 * SSH State machine related code
 */
/* This is the ONLY way to change SSH state! */
static void state(struct connectdata *conn, sshstate nowstate)
{
  struct ssh_conn *sshc = &conn->proto.sshc;
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  /* for debug purposes */
  static const char * const names[] = {
    "SSH_STOP",
    "SSH_INIT",
    "SSH_S_STARTUP",
    "SSH_HOSTKEY",
    "SSH_AUTHLIST",
    "SSH_AUTH_PKEY_INIT",
    "SSH_AUTH_PKEY",
    "SSH_AUTH_PASS_INIT",
    "SSH_AUTH_PASS",
    "SSH_AUTH_AGENT_INIT",
    "SSH_AUTH_AGENT_LIST",
    "SSH_AUTH_AGENT",
    "SSH_AUTH_HOST_INIT",
    "SSH_AUTH_HOST",
    "SSH_AUTH_KEY_INIT",
    "SSH_AUTH_KEY",
    "SSH_AUTH_GSSAPI",
    "SSH_AUTH_DONE",
    "SSH_SFTP_INIT",
    "SSH_SFTP_REALPATH",
    "SSH_SFTP_QUOTE_INIT",
    "SSH_SFTP_POSTQUOTE_INIT",
    "SSH_SFTP_QUOTE",
    "SSH_SFTP_NEXT_QUOTE",
    "SSH_SFTP_QUOTE_STAT",
    "SSH_SFTP_QUOTE_SETSTAT",
    "SSH_SFTP_QUOTE_SYMLINK",
    "SSH_SFTP_QUOTE_MKDIR",
    "SSH_SFTP_QUOTE_RENAME",
    "SSH_SFTP_QUOTE_RMDIR",
    "SSH_SFTP_QUOTE_UNLINK",
    "SSH_SFTP_QUOTE_STATVFS",
    "SSH_SFTP_GETINFO",
    "SSH_SFTP_FILETIME",
    "SSH_SFTP_TRANS_INIT",
    "SSH_SFTP_UPLOAD_INIT",
    "SSH_SFTP_CREATE_DIRS_INIT",
    "SSH_SFTP_CREATE_DIRS",
    "SSH_SFTP_CREATE_DIRS_MKDIR",
    "SSH_SFTP_READDIR_INIT",
    "SSH_SFTP_READDIR",
    "SSH_SFTP_READDIR_LINK",
    "SSH_SFTP_READDIR_BOTTOM",
    "SSH_SFTP_READDIR_DONE",
    "SSH_SFTP_DOWNLOAD_INIT",
    "SSH_SFTP_DOWNLOAD_STAT",
    "SSH_SFTP_CLOSE",
    "SSH_SFTP_SHUTDOWN",
    "SSH_SCP_TRANS_INIT",
    "SSH_SCP_UPLOAD_INIT",
    "SSH_SCP_DOWNLOAD_INIT",
    "SSH_SCP_DOWNLOAD",
    "SSH_SCP_DONE",
    "SSH_SCP_SEND_EOF",
    "SSH_SCP_WAIT_EOF",
    "SSH_SCP_WAIT_CLOSE",
    "SSH_SCP_CHANNEL_FREE",
    "SSH_SESSION_DISCONNECT",
    "SSH_SESSION_FREE",
    "QUIT"
  };

  /* a precaution to make sure the lists are in sync */
  DEBUGASSERT(sizeof(names)/sizeof(names[0]) == SSH_LAST);

  if(sshc->state != nowstate) {
    infof(conn->data, "wolfssh %p state change from %s to %s\n",
          (void *)sshc, names[sshc->state], names[nowstate]);
  }
#endif

  sshc->state = nowstate;
}

static ssize_t wscp_send(struct connectdata *conn, int sockindex,
                         const void *mem, size_t len, CURLcode *err)
{
  ssize_t nwrite = 0;
  (void)conn;
  (void)sockindex; /* we only support SCP on the fixed known primary socket */
  (void)mem;
  (void)len;
  (void)err;

  return nwrite;
}

static ssize_t wscp_recv(struct connectdata *conn, int sockindex,
                         char *mem, size_t len, CURLcode *err)
{
  ssize_t nread = 0;
  (void)conn;
  (void)sockindex; /* we only support SCP on the fixed known primary socket */
  (void)mem;
  (void)len;
  (void)err;

  return nread;
}

/* return number of sent bytes */
static ssize_t wsftp_send(struct connectdata *conn, int sockindex,
                          const void *mem, size_t len, CURLcode *err)
{
  ssize_t nwrite = 0;
  (void)sockindex;
  (void)conn;
  (void)mem;
  (void)len;
  (void)err;

  return nwrite;
}

/*
 * Return number of received (decrypted) bytes
 * or <0 on error
 */
static ssize_t wsftp_recv(struct connectdata *conn, int sockindex,
                          char *mem, size_t len, CURLcode *err)
{
  ssize_t nread = 0;
  (void)conn;
  (void)sockindex;
  (void)mem;
  (void)len;
  (void)err;

  return nread;
}

/*
 * SSH setup and connection
 */
static CURLcode wssh_setup_connection(struct connectdata *conn)
{
  struct SSHPROTO *ssh;

  conn->data->req.protop = ssh = calloc(1, sizeof(struct SSHPROTO));
  if(!ssh)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

static Curl_recv wscp_recv, wsftp_recv;
static Curl_send wscp_send, wsftp_send;

static int userauth(byte authtype,
                    WS_UserAuthData* authdata,
                    void *ctx)
{
  struct connectdata *conn = ctx;
  word32 plen = (word32) strlen(conn->passwd);
  fprintf(stderr, "wolfssh callback: %s type %s\n", __func__,
          authtype == WOLFSSH_USERAUTH_PASSWORD ? "PASSWORD" :
          "PUBLICCKEY");
  authdata->sf.password.password = (byte *)conn->user;
  authdata->sf.password.passwordSz = plen;

  return 0;
}

static CURLcode wssh_connect(struct connectdata *conn, bool *done)
{
  struct Curl_easy *data = conn->data;
  struct ssh_conn *ssh;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  int rc;

  /* initialize per-handle data if not already */
  if(!data->req.protop)
    wssh_setup_connection(conn);

  /* We default to persistent connections. We set this already in this connect
     function to make the re-use checks properly be able to check this bit. */
  connkeep(conn, "SSH default");

  if(conn->handler->protocol & CURLPROTO_SCP) {
    conn->recv[FIRSTSOCKET] = wscp_recv;
    conn->send[FIRSTSOCKET] = wscp_send;
  }
  else {
    conn->recv[FIRSTSOCKET] = wsftp_recv;
    conn->send[FIRSTSOCKET] = wsftp_send;
  }
  ssh = &conn->proto.sshc;
  ssh->ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
  if(!ssh->ctx) {
    failf(data, "No wolfSSH context");
    goto error;
  }

  ssh->ssh_session = wolfSSH_new(ssh->ctx);
  if(ssh->ssh_session == NULL) {
    failf(data, "No wolfSSH session");
    goto error;
  }

  rc = wolfSSH_SetUsername(ssh->ssh_session, conn->user);
  if(rc != WS_SUCCESS) {
    failf(data, "wolfSSH failed to set user name");
    goto error;
  }

  /* set callback for authentication */
  wolfSSH_SetUserAuth(ssh->ctx, userauth);
  wolfSSH_SetUserAuthCtx(ssh->ssh_session, conn);

  rc = wolfSSH_set_fd(ssh->ssh_session, (int)sock);
  if(rc) {
    failf(data, "wolfSSH failed to set socket");
    goto error;
  }

  wolfSSH_Debugging_ON();

  *done = TRUE;
  state(conn, SSH_INIT);

  return wssh_multi_statemach(conn, done);
  error:
  wolfSSH_free(ssh->ssh_session);
  wolfSSH_CTX_free(ssh->ctx);
  return CURLE_FAILED_INIT;
}

/*
 * wssh_statemach_act() runs the SSH state machine as far as it can without
 * blocking and without reaching the end.  The data the pointer 'block' points
 * to will be set to TRUE if the wolfssh function returns EAGAIN meaning it
 * wants to be called again when the socket is ready
 */

static CURLcode wssh_statemach_act(struct connectdata *conn, bool *block)
{
  CURLcode result = CURLE_OK;
  struct ssh_conn *sshc = &conn->proto.sshc;
  struct Curl_easy *data = conn->data;
#if 0
  struct SSHPROTO *ssh = data->req.protop;
#endif
  int rc;
  *block = FALSE; /* we're not blocking by default */

  do {
    switch(sshc->state) {
    case SSH_INIT:
      state(conn, SSH_S_STARTUP);
      /* FALLTHROUGH */
    case SSH_S_STARTUP:
      rc = wolfSSH_connect(sshc->ssh_session);
      infof(data, "wolfSSH_connect returns %d\n", rc);
      if(rc == WS_WANT_READ) {
        *block = TRUE;
        conn->waitfor = KEEP_RECV;
        return CURLE_OK;
      }
      else if(rc == WS_WANT_WRITE) {
        *block = TRUE;
        conn->waitfor = KEEP_RECV;
        return CURLE_OK;
      }
      else if(rc != WS_SUCCESS) {
        state(conn, SSH_STOP);
        return CURLE_SSH;
      }
      infof(data, "wolfssh connected!\n");
      if(conn->handler->protocol & CURLPROTO_SFTP)
        state(conn, SSH_SFTP_INIT);
      else
        state(conn, SSH_STOP);
      break;
    case SSH_STOP:
      break;
    case SSH_SFTP_INIT:
      rc = wolfSSH_SFTP_connect(sshc->ssh_session);
      if((rc == WS_WANT_READ) || (rc == WS_WANT_WRITE)) {
        *block = TRUE;
        return CURLE_OK;
      }
      else if(rc == WS_SUCCESS) {
        infof(data, "wolfssh SFTP connected!\n");
        state(conn, SSH_STOP);
      }
      else {
        failf(data, "wolfssh SFTP connect error %d", rc);
        return CURLE_SSH;
      }
      break;
    default:
      break;
    }
  } while(1);
  return result;
}

/* called repeatedly until done from multi.c */
static CURLcode wssh_multi_statemach(struct connectdata *conn, bool *done)
{
  struct ssh_conn *sshc = &conn->proto.sshc;
  CURLcode result = CURLE_OK;
  bool block; /* we store the status and use that to provide a ssh_getsock()
                 implementation */
  do {
    result = wssh_statemach_act(conn, &block);
    *done = (sshc->state == SSH_STOP) ? TRUE : FALSE;
    /* if there's no error, it isn't done and it didn't EWOULDBLOCK, then
       try again */
  } while(!result && !*done && !block);

  return result;
}

static CURLcode wssh_do(struct connectdata *conn, bool *done)
{
  CURLcode result = CURLE_OK;
  (void)conn;
  (void)done;

  return result;
}

static CURLcode wscp_done(struct connectdata *conn,
                         CURLcode code, bool premature)
{
  CURLcode result = CURLE_OK;
  (void)conn;
  (void)code;
  (void)premature;

  return result;
}

static CURLcode wscp_doing(struct connectdata *conn,
                          bool *dophase_done)
{
  CURLcode result = CURLE_OK;
  (void)conn;
  (void)dophase_done;

  return result;
}

static CURLcode wscp_disconnect(struct connectdata *conn, bool dead_connection)
{
  CURLcode result = CURLE_OK;
  (void)conn;
  (void)dead_connection;

  return result;
}

static CURLcode wsftp_done(struct connectdata *conn,
                          CURLcode code, bool premature)
{
  CURLcode result = CURLE_OK;
  (void)conn;
  (void)code;
  (void)premature;

  return result;
}

static CURLcode wsftp_doing(struct connectdata *conn,
                           bool *dophase_done)
{
  CURLcode result = CURLE_OK;
  (void)conn;
  (void)dophase_done;

  return result;
}

static CURLcode wsftp_disconnect(struct connectdata *conn, bool dead)
{
  CURLcode result = CURLE_OK;
  (void)conn;
  (void)dead;

  return result;
}

static int wssh_getsock(struct connectdata *conn,
                       curl_socket_t *sock, /* points to numsocks number
                                               of sockets */
                       int numsocks)
{
  CURLcode result = CURLE_OK;
  (void)conn;
  (void)sock;
  (void)numsocks;

  return result;
}

static int wssh_perform_getsock(const struct connectdata *conn,
                               curl_socket_t *sock, /* points to numsocks
                                                       number of sockets */
                               int numsocks)
{
  CURLcode result = CURLE_OK;
  (void)conn;
  (void)sock;
  (void)numsocks;

  return result;
}

#endif /* USE_WOLFSSH */
