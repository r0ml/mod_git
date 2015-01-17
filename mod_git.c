
/* 
 On Linux build with:
 
  sudo apxs -i -c mod_git.c -lgit2
 
 */

#include <stdio.h>

#include "apr_strings.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "util_script.h"
#include "http_main.h"
#include "http_request.h"

#include "util_cookies.h"

#include "mod_core.h"
#include "http_core.h"

#include <stdio.h>
#include <string.h>
#include <git2.h>
#include <time.h>

extern module git_module;

typedef struct asset_struct {
    char commit_id[42];
    char tree_id[42];
    size_t len;
    git_time_t timestamp;
    char bytes[1];
} asset;

typedef struct git_dir_config {
    git_repository *repo;
    const char *repo_path;
    const char *default_vursion;
    const char *path;
    apr_hash_t *map_tag_to_commit;
    time_t map_age;
} git_dir_config;

/* getAsset:  given a repository, a commitish, and a filname, retrieve
   the specified version of the file from the repo, and return a pointer
   to the contents which have been loaded into memory */
asset* getAsset(git_repository *repo, const char *v, const char *fnam) {
    // if (v == NULL || strlen(v) == 0) return getWorking(fnam);
    asset *result = NULL;
    git_object *obj;
    int n = git_revparse_single(&obj, repo, v);
    if (n != 0) return result;
    const git_oid *oi = git_object_id(obj);
    
    char ois[42];
    git_oid_fmt(ois,oi);
  
    git_commit *gc;
    git_commit_lookup(&gc, repo, oi);
    
    git_time_t gct = git_commit_time(gc);

    const git_oid* ci = git_commit_tree_id(gc);
    char cis[42];
    git_oid_fmt(cis, ci);
    
    git_tree *tree;
    n = git_tree_lookup(&tree, repo, ci);
    if (n != 0) goto tlf;
    
    git_tree_entry *te;
    n = git_tree_entry_bypath(&te, tree, fnam);
    if (n != 0) goto tebf;
    
    const git_oid *bi = git_tree_entry_id(te);
    
    git_blob *bl;
    n = git_blob_lookup(&bl,repo,bi);
    if (n != 0) goto blf;
    
    git_off_t siz = git_blob_rawsize(bl);
    const char *z = (const char *)git_blob_rawcontent(bl);
    
    result = malloc(sizeof(asset) + siz);
    memcpy(result->commit_id, ois, 40);
    result->commit_id[40]='\0';
    memcpy(result->tree_id, cis, 40);
    result->tree_id[40]='\0';
    result->len = siz;
    result->timestamp = gct;
    
    memcpy(result->bytes, z, siz);
    git_blob_free(bl);
blf:;
    git_tree_entry_free(te);
tebf:;
    git_tree_free(tree);
tlf:;
    git_commit_free(gc);
    git_object_free(obj);

    return result;
}

/* if using threads, git needs to be initialized for threads */
static void git_child_init(apr_pool_t *pool, server_rec *s) {
    git_threads_init();
}


static apr_status_t init_repo(request_rec *r, git_dir_config *gdc) {
    if (gdc->repo == NULL) {
        git_repository *repo;
        if (gdc->repo_path == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01235)
                          "git handler has no GitRepo path defined");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        int n = git_repository_open(&repo, gdc->repo_path);
        if (n!=0) {
            const git_error *ge = giterr_last();
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(09039)
                          "git_repository_open failed for %s: %s", gdc->path, ge->message);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        else {
            gdc-> repo = repo;
        }
    }
    return OK;
}

static int git_handler(request_rec *r) {
    apr_status_t rv;

    if (strcmp(r->handler, "git")) {
        return DECLINED;
    }
    
    r->allowed |= (AP_METHOD_BIT << M_GET);
    if (r->method_number != M_GET) {
        return DECLINED;
    }
  
    git_dir_config *gdc = (git_dir_config *) ap_get_module_config(r->per_dir_config, &git_module);
    
    const char *tag;
    ap_cookie_read(r, "git-tag", &tag, 0);
    if (tag == NULL) tag = gdc->default_vursion; // put the default back

    size_t st = tag == NULL ? 0 : strlen(tag);
    int workv = st == 0 || (st == 1 && *tag == '-');

    // if I want files from working directory, let the normal Apache mechanism handle it.
    //    if (workv) return DECLINED;
    
    
    apr_file_t *workf = NULL;
    
    const char *pi = r->filename + strlen( ap_document_root(r)); //  gdc->path);
    const char *fnam = NULL;
    apr_finfo_t finfo;

    while(*pi == '/') pi++;
    
    if (workv) {
/*      if (r->finfo.filetype == APR_NOFILE) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(01233)
        "File does not exist: %s", r->filename);
        return HTTP_NOT_FOUND;
      }
 */
        
      fnam = ap_make_full_path(r->pool, gdc->repo_path, pi);

      apr_status_t rv = apr_stat(&finfo, fnam, APR_FINFO_TYPE, r->pool);
      if (rv != APR_SUCCESS || finfo.filetype == APR_DIR) {
          return HTTP_NOT_FOUND;
      }
        

      if ((rv = apr_file_open(&workf, fnam, APR_READ, APR_OS_DEFAULT, r->pool)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01234)
        "file permissions deny server access: %s", fnam);
        return HTTP_FORBIDDEN;
      }
    }
    
    if (!r->header_only) {
        conn_rec *c = r->connection;
        apr_bucket_brigade *bb;
        apr_bucket *b;

        bb = apr_brigade_create(r->pool, c->bucket_alloc);
        
        if (workv) {
            
            ap_update_mtime(r, finfo.mtime);
            ap_set_last_modified(r);
            apr_brigade_insert_file(bb, workf, 0, finfo.size, r->pool);
            ap_set_etag(r);
        } else {
            apr_status_t ss = init_repo(r, gdc);
            if (ss != OK) return ss;
            
            const char *tv = tag;
            const char *commit = NULL;
            if ( time(NULL) - gdc->map_age > 5 ) {
                // fprintf(stderr, "clear hash\n");
                apr_hash_clear(gdc->map_tag_to_commit);
                gdc->map_age = time(NULL);
            }
            else {
                commit = apr_hash_get(gdc->map_tag_to_commit, tag, strlen(tag));
                // fprintf(stderr, "looked up hash %s and got %s\n", tag, commit);
            }
            if ( commit != NULL) tv = commit;

            // fprintf(stderr, "tv = %s, pi = %s\n", tv, pi);
            asset *asn = getAsset( gdc->repo, tv, pi );
            
            
            if (asn == NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(01233)
                              "File '%s' does not exist in version '%s'", pi, tag);
                    return HTTP_NOT_FOUND;
            }
            if (commit == NULL) {
                // fprintf(stderr, "stored commit %s for %s\n", asn->commit_id, tag);
                apr_hash_set(gdc->map_tag_to_commit, tag, strlen(tag),
                         apr_pstrdup(r->server->process->pool, asn->commit_id));
//                ap_cookie_write(r, "git-commit", asn->commit_id, "path=/", ONE_YEAR, r->headers_out, NULL);
            }
            apr_table_add(r->headers_out,"X-Commit", asn->commit_id);
            apr_table_setn(r->headers_out,"ETag",   apr_pstrdup(r->pool, asn->commit_id) );
            apr_table_unset(r->notes,"no-etag");
            r->mtime = asn->timestamp * 1000000;
            ap_set_last_modified(r);
            
            apr_brigade_write(bb, NULL, NULL, asn->bytes, asn->len);
            free(asn);
        }

        b = apr_bucket_eos_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        rv = ap_pass_brigade(r->output_filters, bb);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01236)
                          "mod_git: ap_pass_brigade failed for file %s", pi);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    else {
        if (workv) { apr_file_close(workf); }
    }
    
    return OK; // OK is ambiguous -- should be 0
}

int xpr(void *rec, const char *key, const char *val) {
    printf("%s: %s\n", key, val);
    return 1;
}

void dump_table(apr_table_t *t) {
    apr_table_do(xpr, NULL, t, NULL);
}


/*
typedef struct inmem {
    asset *data;
    size_t offset;
} inmem;

apr_status_t inmem_gets(void *buf, apr_size_t bufsiz, void *params) {
    inmem *p = (inmem *)params;
    // End of array reached?
    if (p->offset >= p->data->len) return NULL;
    
    // return the line
    const char *st = p->data->bytes + p->offset;
    char *linx = memchr( &(p->data->bytes) + p->offset, '\n', p->data->len - p->offset);
    size_t noff = linx - p->data->bytes;
    size_t neff = noff - p->offset >= bufsiz-1 ? bufsiz-1 : noff - p->offset;
    memcpy(buf, st, neff);
    char *bufc = (char *)buf;
    bufc[neff]='\0';
    p->offset = noff;
    return buf;
}

apr_status_t inmem_close(void *params) {
    inmem *p = (inmem *)params;
    p->offset = p->data->len;
    return 0;
}
*/

/*
static apr_status_t git_open_htaccess(request_rec *r, const char *dir_name, const char *access_name, ap_configfile_t **conffile, const char **full_name) {
    
    git_dir_config *gdc = (git_dir_config *) ap_get_module_config(r->per_dir_config, &git_module);

    apr_status_t ss = init_repo(r, gdc);
    if (ss != OK) return AP_DECLINED;
        
    const char *pi = dir_name + strlen(gdc->path);
    while(*pi == '/') pi++;

    
    *full_name = ap_make_full_path(r->pool, pi, access_name);
    
    
    const char *tag;
    ap_cookie_read(r, "git-tag", &tag, 0);
    if (tag == NULL) tag = gdc->default_vursion; // put the default back
    
    size_t st = tag == NULL ? 0 : strlen(tag);
    int workv = st == 0 || (st == 1 && *tag == '-');
    
    // if I want files from working directory, let the normal Apache mechanism handle it.
    if (workv) return DECLINED;
    
    
    
    asset *ass = getAsset(gdc->repo, tag, *full_name);
    
    inmem *ppp = apr_pcalloc( r->pool, sizeof(inmem));
    ppp->data = ass;
    ppp->offset = 0;
    ap_configfile_t *acf = ap_pcfg_open_custom(r->pool, *full_name, ppp, NULL, &inmem_gets, &inmem_close);
    *conffile = acf;

    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 909, r, "htaccess open: %s %s %s", dir_name, access_name, pi);
    
    return OK;
}
 */

/* This implementation does not look for and process .htaccess files.
   Take a look at  server/request.c  in httpd for how that happens during 
   directory walking.   It should be possible to look for .htaccess files in the
   repo and duplicate that processing.
 
   Currently, we are not using .htaccess files, so there is limited urgency.
 */

static int git_trans(request_rec *r) {
    git_dir_config *gdc = ap_get_module_config(r->per_dir_config, &git_module);
    if (gdc->path == NULL) return DECLINED;
    
    r->handler="git";
    // do I set r->filename ?
    
    return OK;
}

static int git_map_location(request_rec *r) {
    git_dir_config *gdc = ap_get_module_config(r->per_dir_config, &git_module);
    if (r->handler != NULL && strcmp(r->handler,"git") == 0) return OK;
    // if (gdc->path == NULL) return DECLINED;
    return OK; // bypasses core map_to_storage
    
    /*
    git_server_conf *sconf = ap_get_module_config(r->server_module_config, &git_module);
    
    git_dir_config *entry_git;
    ap_conf_vector_t *entry_config;
    int num_sec = sconf->sec_git->nelts;
    
    
    
    if (gdc->path == NULL) return DECLINED;
    
    int access_status = git_get(r);
    if (access_status) {
        ap_die(access_status, r);
        return access_status;
    }
    return OK;
     */
}

/*
static int git_fixup(request_rec *r) {
    git_dir_config *gdc = ap_get_module_config(r->per_dir_config, &git_module);
    fprintf(stderr, "%s\n", r->filename);
    return DECLINED;
}
*/

static void register_hooks(apr_pool_t *p) {
    /* fixup before mod_rewrite, so that the proxied url will not
     * escaped accidentally by our fixup.
     */
    static const char * const aszSucc[] = { "mod_rewrite.c", NULL};

    ap_hook_handler(git_handler,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_child_init(git_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    
    // filename-to-URI translation -- this is where I figure out I need to use git
    ap_hook_translate_name(git_trans, aszSucc, NULL, APR_HOOK_FIRST );
    
    // suppress the file system access
    ap_hook_map_to_storage(git_map_location, NULL, aszSucc, APR_HOOK_FIRST);
    
    // ap_hook_fixups(git_fixup, NULL, aszSucc, APR_HOOK_FIRST);
    
    // ap_hook_open_htaccess(git_open_htaccess, NULL, NULL, APR_HOOK_FIRST);
    git_threads_init();
}

static const char *init_git_config(cmd_parms *cmd, void *dconf, const char *rp, const char *dv) {
    git_dir_config *gdc = (git_dir_config *)dconf;
    gdc->default_vursion = apr_pstrdup(cmd->pool, dv);
    gdc->path = cmd->path == NULL || 0 == strlen(cmd->path) ? NULL : apr_pstrdup(cmd->pool, cmd->path);
    gdc->repo_path = apr_pstrdup(cmd->pool, rp);
    if (NULL == cmd->directive->parent) {
        // this means server level config
        return NULL;
    }
    // const char *parent = cmd->directive->parent->directive;

    /*
     if (0 == strcasecmp("<Location", parent)) {
        return "Git in <Location> or <LocationMatch> stanza not supported -- use <Directory>";
    }
     */
    
    return NULL;
}

static void *create_git_dir_config(apr_pool_t *pool, char *d) {
    git_dir_config *n = (git_dir_config *)apr_pcalloc(pool, sizeof(git_dir_config));
    n->default_vursion = "-";
    n->map_tag_to_commit = apr_hash_make(pool);
    n->map_age = time(NULL);
    return n;
}

static const command_rec git_cmds[] = {
    AP_INIT_TAKE2("GitRepo", init_git_config, NULL, RSRC_CONF|ACCESS_CONF, "Git repo and default branch"),
    {NULL}
};

AP_DECLARE_MODULE(git) = {
    STANDARD20_MODULE_STUFF,
    create_git_dir_config,  /* create per-directory config structure */
    NULL,                   /* merge per-directory config structures */
    NULL,                   /* create per-server config structure */
    NULL,                   /* merge per-server config structures */
    git_cmds,               /* command apr_table_t */
    register_hooks          /* register hooks */
};

