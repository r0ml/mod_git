
#if defined(__APPLE__)
#include "apache2/httpd.h"
#include "apache2/http_log.h"
#include "apache2/http_request.h"

#include "apache2/util_filter.h"
#include "apache2/util_script.h"
#include "apache2/mod_include.h"

#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_poll.h"
#include "apr_buckets.h"

#include "apache2/ap_mpm.h"

#else
#include "httpd.h"
#include "http_log.h"
#include "http_request.h"

#include "util_filter.h"
#include "util_script.h"
#include "mod_include.h"

#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_poll.h"
#include "apr_buckets.h"

#include "ap_mpm.h"
#endif


/* Soak up stderr from a script and redirect it to the error log.
 */
static apr_status_t log_script_err(request_rec *r, apr_file_t *script_err)
{
    char argsbuffer[HUGE_STRING_LEN];
    char *newline;
    apr_status_t rv;
    
    while ((rv = apr_file_gets(argsbuffer, HUGE_STRING_LEN,
                               script_err)) == APR_SUCCESS) {
        newline = strchr(argsbuffer, '\n');
        if (newline) {
            *newline = '\0';
        }
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01215)
                      "%s", argsbuffer);
    }
    
    return rv;
}

static void discard_script_output(apr_bucket_brigade *bb)
{
    apr_bucket *e;
    const char *buf;
    apr_size_t len;
    apr_status_t rv;
    
    for (e = APR_BRIGADE_FIRST(bb);
         e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e))
    {
        if (APR_BUCKET_IS_EOS(e)) {
            break;
        }
        rv = apr_bucket_read(e, &buf, &len, APR_BLOCK_READ);
        if (rv != APR_SUCCESS) {
            break;
        }
    }
}


#if APR_FILES_AS_SOCKETS

static apr_status_t cgi_bucket_read(apr_bucket *b, const char **str,
                                    apr_size_t *len, apr_read_type_e block);

struct cgi_bucket_data {
    apr_pollset_t *pollset;
    request_rec *r;
};

/* A CGI bucket type is needed to catch any output to stderr from the
 * script; see PR 22030. */
static const apr_bucket_type_t bucket_type_cgi = {
    "CGI", 5, APR_BUCKET_DATA,
    apr_bucket_destroy_noop,
    cgi_bucket_read,
    apr_bucket_setaside_notimpl,
    apr_bucket_split_notimpl,
    apr_bucket_copy_notimpl
};


/* Create a duplicate CGI bucket using given bucket data */
static apr_bucket *cgi_bucket_dup(struct cgi_bucket_data *data,
                                  apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);
    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b->type = &bucket_type_cgi;
    b->length = (apr_size_t)(-1);
    b->start = -1;
    b->data = data;
    return b;
}

/* Handle stdout from CGI child.  Duplicate of logic from the _read
 * method of the real APR pipe bucket implementation. */
static apr_status_t cgi_read_stdout(apr_bucket *a, apr_file_t *out,
                                    const char **str, apr_size_t *len)
{
    char *buf;
    apr_status_t rv;
    
    *str = NULL;
    *len = APR_BUCKET_BUFF_SIZE;
    buf = apr_bucket_alloc(*len, a->list); /* XXX: check for failure? */
    
    rv = apr_file_read(out, buf, len);
    
    if (rv != APR_SUCCESS && rv != APR_EOF) {
        apr_bucket_free(buf);
        return rv;
    }
    
    if (*len > 0) {
        struct cgi_bucket_data *data = a->data;
        apr_bucket_heap *h;
        
        /* Change the current bucket to refer to what we read */
        a = apr_bucket_heap_make(a, buf, *len, apr_bucket_free);
        h = a->data;
        h->alloc_len = APR_BUCKET_BUFF_SIZE; /* note the real buffer size */
        *str = buf;
        APR_BUCKET_INSERT_AFTER(a, cgi_bucket_dup(data, a->list));
    }
    else {
        apr_bucket_free(buf);
        a = apr_bucket_immortal_make(a, "", 0);
        *str = a->data;
    }
    return rv;
}

/* Read method of CGI bucket: polls on stderr and stdout of the child,
 * sending any stderr output immediately away to the error log. */
static apr_status_t cgi_bucket_read(apr_bucket *b, const char **str,
                                    apr_size_t *len, apr_read_type_e block)
{
    struct cgi_bucket_data *data = b->data;
    apr_interval_time_t timeout;
    apr_status_t rv;
    int gotdata = 0;
    
    timeout = block == APR_NONBLOCK_READ ? 0 : data->r->server->timeout;
    
    do {
        const apr_pollfd_t *results;
        apr_int32_t num;
        
        rv = apr_pollset_poll(data->pollset, timeout, &num, &results);
        if (APR_STATUS_IS_TIMEUP(rv)) {
            if (timeout) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, data->r, APLOGNO(01220)
                              "Timeout waiting for output from CGI script %s",
                              data->r->filename);
                return rv;
            }
            else {
                return APR_EAGAIN;
            }
        }
        else if (APR_STATUS_IS_EINTR(rv)) {
            continue;
        }
        else if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, data->r, APLOGNO(01221)
                          "poll failed waiting for CGI child");
            return rv;
        }
        
        for (; num; num--, results++) {
            if (results[0].client_data == (void *)1) {
                /* stdout */
                rv = cgi_read_stdout(b, results[0].desc.f, str, len);
                if (APR_STATUS_IS_EOF(rv)) {
                    rv = APR_SUCCESS;
                }
                gotdata = 1;
            } else {
                /* stderr */
                apr_status_t rv2 = log_script_err(data->r, results[0].desc.f);
                if (APR_STATUS_IS_EOF(rv2)) {
                    apr_pollset_remove(data->pollset, &results[0]);
                }
            }
        }
        
    } while (!gotdata);
    
    return rv;
}


/* Create a CGI bucket using pipes from script stdout 'out'
 * and stderr 'err', for request 'r'. */
static apr_bucket *cgi_bucket_create(request_rec *r,
                                     apr_file_t *out, apr_file_t *err,
                                     apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);
    apr_status_t rv;
    apr_pollfd_t fd;
    struct cgi_bucket_data *data = apr_palloc(r->pool, sizeof *data);
    
    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b->type = &bucket_type_cgi;
    b->length = (apr_size_t)(-1);
    b->start = -1;
    
    /* Create the pollset */
    rv = apr_pollset_create(&data->pollset, 2, r->pool, 0);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01217)
                      "apr_pollset_create(); check system or user limits");
        return NULL;
    }
    
    fd.desc_type = APR_POLL_FILE;
    fd.reqevents = APR_POLLIN;
    fd.p = r->pool;
    fd.desc.f = out; /* script's stdout */
    fd.client_data = (void *)1;
    rv = apr_pollset_add(data->pollset, &fd);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01218)
                      "apr_pollset_add(); check system or user limits");
        return NULL;
    }
    
    fd.desc.f = err; /* script's stderr */
    fd.client_data = (void *)2;
    rv = apr_pollset_add(data->pollset, &fd);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01219)
                      "apr_pollset_add(); check system or user limits");
        return NULL;
    }
    
    data->r = r;
    b->data = data;
    return b;
}

#endif


typedef enum {RUN_AS_SSI, RUN_AS_CGI} prog_types;

typedef struct {
    apr_int32_t          in_pipe;
    apr_int32_t          out_pipe;
    apr_int32_t          err_pipe;
    int                  process_cgi;
    apr_cmdtype_e        cmd_type;
    apr_int32_t          detached;
    prog_types           prog_type;
    apr_bucket_brigade **bb;
    include_ctx_t       *ctx;
    ap_filter_t         *next;
    apr_int32_t          addrspace;
} cgi_exec_info_t;

static void cgi_child_errfn(apr_pool_t *pool, apr_status_t err,
                            const char *description)
{
    apr_file_t *stderr_log;
    
    apr_file_open_stderr(&stderr_log, pool);
    /* Escape the logged string because it may be something that
     * came in over the network.
     */
    apr_file_printf(stderr_log,
                    "(%d)%pm: %s\n",
                    err,
                    &err,
#ifndef AP_UNSAFE_ERROR_LOG_UNESCAPED
                    ap_escape_logitem(pool,
#endif
                                      description
#ifndef AP_UNSAFE_ERROR_LOG_UNESCAPED
                                      )
#endif
                    );
}

static apr_status_t run_cgi_child(apr_file_t **script_out,
                                  apr_file_t **script_in,
                                  apr_file_t **script_err,
                                  const char *command,
                                  const char * const argv[],
                                  request_rec *r,
                                  apr_pool_t *p,
                                  cgi_exec_info_t *e_info)
{
    const char * const *env;
    apr_procattr_t *procattr;
    apr_proc_t *procnew;
    apr_status_t rc = APR_SUCCESS;
    
#ifdef AP_CGI_USE_RLIMIT
    core_dir_config *conf = ap_get_core_module_config(r->per_dir_config);
#endif
    
    RAISE_SIGSTOP(CGI_CHILD);
    
    env = (const char * const *)ap_create_environment(p, r->subprocess_env);
        
    /* Transmute ourselves into the script.
     * NB only ISINDEX scripts get decoded arguments.
     */
    if (((rc = apr_procattr_create(&procattr, p)) != APR_SUCCESS) ||
        ((rc = apr_procattr_io_set(procattr,
                                   e_info->in_pipe,
                                   e_info->out_pipe,
                                   e_info->err_pipe)) != APR_SUCCESS) ||
        ((rc = apr_procattr_dir_set(procattr,
                                    ap_make_dirstr_parent(r->pool,
                                                          "/tmp" // r->filename
                                                          ))) != APR_SUCCESS) ||
#if defined(RLIMIT_CPU) && defined(AP_CGI_USE_RLIMIT)
        ((rc = apr_procattr_limit_set(procattr, APR_LIMIT_CPU,
                                      conf->limit_cpu)) != APR_SUCCESS) ||
#endif
#if defined(AP_CGI_USE_RLIMIT) && (defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_AS))
        ((rc = apr_procattr_limit_set(procattr, APR_LIMIT_MEM,
                                      conf->limit_mem)) != APR_SUCCESS) ||
#endif
#if defined(RLIMIT_NPROC) && defined(AP_CGI_USE_RLIMIT)
        ((rc = apr_procattr_limit_set(procattr, APR_LIMIT_NPROC,
                                      conf->limit_nproc)) != APR_SUCCESS) ||
#endif
        ((rc = apr_procattr_cmdtype_set(procattr,
                                        e_info->cmd_type)) != APR_SUCCESS) ||
        
        ((rc = apr_procattr_detach_set(procattr,
                                       e_info->detached)) != APR_SUCCESS) ||
        ((rc = apr_procattr_addrspace_set(procattr,
                                          e_info->addrspace)) != APR_SUCCESS) ||
        ((rc = apr_procattr_child_errfn_set(procattr, cgi_child_errfn)) != APR_SUCCESS)) {
        /* Something bad happened, tell the world. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r, APLOGNO(01216)
                      "couldn't set child process attributes: %s", r->filename);
    }
    else {
        procnew = apr_pcalloc(p, sizeof(*procnew));
        rc = ap_os_create_privileged_process(r, procnew, command, argv, env,
                                             procattr, p);
        
        if (rc != APR_SUCCESS) {
            /* Bad things happened. Everyone should have cleaned up. */
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_TOCLIENT, rc, r,
                          "couldn't create child process: %d: %s", rc,
                          apr_filepath_name_get(r->filename));
        }
        else {
            apr_pool_note_subprocess(p, procnew, APR_KILL_AFTER_TIMEOUT);
            
            *script_in = procnew->out;
            if (!*script_in)
                return APR_EBADF;
            apr_file_pipe_timeout_set(*script_in, r->server->timeout);
            
            if (e_info->prog_type == RUN_AS_CGI) {
                *script_out = procnew->in;
                if (!*script_out)
                    return APR_EBADF;
                apr_file_pipe_timeout_set(*script_out, r->server->timeout);
                
                *script_err = procnew->err;
                if (!*script_err)
                    return APR_EBADF;
                apr_file_pipe_timeout_set(*script_err, r->server->timeout);
            }
        }
    }
    return (rc);
}

/* There can be two cases:
 If it is a GET, then there is no STDIN, so call the script and get the output
 
 If it is a POST, then there is input data, so the script needs to have a file descriptor
 which it can read from to get the data
 */

apr_status_t callScript(request_rec *r, const char *scr, apr_size_t scrlen) {
    cgi_exec_info_t e_info;
    
    ap_add_common_vars(r);
    ap_add_cgi_vars(r);
    
    e_info.process_cgi = 1;
    e_info.cmd_type    = APR_SHELLCMD_ENV; // APR_PROGRAM;
    e_info.detached    = 0;
    e_info.in_pipe     = APR_CHILD_BLOCK;
    e_info.out_pipe    = APR_CHILD_BLOCK;
    e_info.err_pipe    = APR_CHILD_BLOCK;
    e_info.prog_type   = RUN_AS_CGI;
    e_info.bb          = NULL;
    e_info.ctx         = NULL;
    e_info.next        = NULL;
    e_info.addrspace   = 0;
    
    apr_status_t rv;
    apr_file_t *xfile;
    const char *xfildir;
    
    
    apr_temp_dir_get(&xfildir, r->pool);
    
    char *ffxnam = apr_pstrcat(r->pool, xfildir, "/executableXXXXXX", NULL);
    
    rv = apr_file_mktemp(& xfile, ffxnam, 0 , r->pool);
    
    rv = apr_file_write_full(xfile, scr, scrlen, NULL);
    
    //    rv = apr_file_attrs_set(ffxnam, APR_FILE_ATTR_READONLY | APR_FILE_ATTR_EXECUTABLE, APR_FILE_ATTR_READONLY | APR_FILE_ATTR_EXECUTABLE, r->pool);
    rv = apr_file_perms_set(ffxnam, 0x0555);
    
    apr_file_t *script_out = NULL, *script_in = NULL, *script_err = NULL;
    
    const char *command;
    const char **argv;
    apr_bucket_brigade *bb;
    apr_bucket *b;
    int seen_eos, child_stopped_reading;
    
    int numwords = 0;
    int idx = 1;
    command = ffxnam; // means that executables will not work!
    argv = apr_palloc(r->pool, (numwords + 2) * sizeof(char *));
    argv[0] = command;
    for (int x = 1; x < numwords; x++) {
        //        w = ap_getword_nulls(r->pool, &args, '+');
        //        ap_unescape_url(w);
        //        argv[idx++] = ap_escape_shell_cmd(r->pool, w);
    }
    argv[idx] = NULL;
    
    
    /* run the script in its own process */
    if ((rv = run_cgi_child(&script_out, &script_in, &script_err,
                            command, argv, r, r->pool,
                            &e_info)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01227)
                      "couldn't spawn child process: %s", r->filename);
        return rv;
    }
    
    /* Transfer any put/post args, CERN style...
     * Note that we already ignore SIGPIPE in the core server.
     */
    
    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    seen_eos = 0;
    child_stopped_reading = 0;
    
    do {
        apr_bucket *bucket;
        
        rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                            APR_BLOCK_READ, HUGE_STRING_LEN);
        
        if (rv != APR_SUCCESS) {
            if (APR_STATUS_IS_TIMEUP(rv)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01224)
                              "Timeout during reading request entity data");
                return HTTP_REQUEST_TIME_OUT;
            }
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01225)
                          "Error reading request entity data");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        
        for (bucket = APR_BRIGADE_FIRST(bb);
             bucket != APR_BRIGADE_SENTINEL(bb);
             bucket = APR_BUCKET_NEXT(bucket))
        {
            const char *data;
            apr_size_t len;
            
            if (APR_BUCKET_IS_EOS(bucket)) {
                seen_eos = 1;
                break;
            }
            
            // We can't do much with this.
            if (APR_BUCKET_IS_FLUSH(bucket)) {
                continue;
            }
            
            // If the child stopped, we still must read to EOS.
            if (child_stopped_reading) {
                continue;
            }
            
            // read
            apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);
            
            // Keep writing data to the child until done or too much time
            // elapses with no progress or an error occurs.
            rv = apr_file_write_full(script_out, data, len, NULL);
            
            if (rv != APR_SUCCESS) {
                // silly script stopped reading, soak up remaining message
                child_stopped_reading = 1;
            }
        }
        apr_brigade_cleanup(bb);
    }
    while (!seen_eos);
    
    // Is this flush really needed?
    apr_file_flush(script_out);
    apr_file_close(script_out);
    
    AP_DEBUG_ASSERT(script_in != NULL);
    
    apr_brigade_cleanup(bb);
    
#if APR_FILES_AS_SOCKETS
    apr_file_pipe_timeout_set(script_in, 0);
    apr_file_pipe_timeout_set(script_err, 0);
    
    b = cgi_bucket_create(r, script_in, script_err, r->connection->bucket_alloc);
    if (b == NULL)
        return HTTP_INTERNAL_SERVER_ERROR;
#else
    b = apr_bucket_pipe_create(script_in, c->bucket_alloc);
#endif
    APR_BRIGADE_INSERT_TAIL(bb, b);
    b = apr_bucket_eos_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    
    rv = ap_pass_brigade(r->output_filters, bb);
    
    /* don't soak up script output if errors occurred writing it
     * out...  otherwise, we prolong the life of the script when the
     * connection drops or we stopped sending output for some other
     * reason */
    if (rv == APR_SUCCESS && !r->connection->aborted) {
        apr_file_pipe_timeout_set(script_err, r->server->timeout);
        log_script_err(r, script_err);
    }
    
    apr_file_close(script_err);
    
    return OK;                      /* NOT r->status, even if it has changed. */
    
}

