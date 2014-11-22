
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

#define GIT_MAGIC_TYPE "httpd/git"

#define ONE_YEAR 31536000

/* HOME must be set to a directory that the httpd daemon has access to -- otherwise 
   the attempt to open the git repository will fail */

extern module git_module;

typedef struct asset_struct {
    char commit_id[42];
    char tree_id[42];
    size_t len;
    git_time_t timestamp;
    char bytes[1];
} asset;

struct git_dir_config {
    git_repository *repo;
//    const char *repo_path;
    const char *default_vursion;
    const char *path;
    int location;
};

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

static void git_child_init(apr_pool_t *pool, server_rec *s) {
    git_threads_init();
}


void git_request(request_rec *r, const char **tag, const char **commit) {
}

static int git_handler(request_rec *r) {
    apr_status_t rv;

    if (strcmp(r->handler, GIT_MAGIC_TYPE) && strcmp(r->handler, "git")) {
        return DECLINED;
    }
    
    r->allowed |= (AP_METHOD_BIT << M_GET);
    if (r->method_number != M_GET) {
        return DECLINED;
    }
  
    struct git_dir_config *gdc = (struct git_dir_config *) ap_get_module_config(r->per_dir_config, &git_module);
    
    core_dir_config *cd = ap_get_core_module_config(r->per_dir_config);
    core_request_config *core = ap_get_core_module_config(r->request_config);

    
    const char *tag, *commit;
    const char *df = gdc->default_vursion;
    tag = df;
    ap_cookie_read(r, "git-tag", &tag, 0);
    const char *dn = apr_table_get(r->headers_in, "git-tag");
    if (dn != NULL) tag = dn;
    ap_cookie_read(r, "git-commit", &commit, 0);
    
    if (tag == NULL) tag = df; // put the default back
    
    apr_table_t *qtable;
    ap_args_to_table(r, &qtable);
    const char *vurs = apr_table_get(qtable, "vursion");
    if (vurs != NULL) {
        tag = vurs;
        commit = NULL;
        // catches internal redirects
        apr_table_setn(r->headers_in, "git-tag", tag);
        ap_cookie_write(r, "git-tag", tag, "path=/", ONE_YEAR, r->headers_out, NULL );
    }
    size_t st = tag == NULL ? 0 : strlen(tag);
    int workv = st == 0 || (st == 1 && *tag == '-');

    // if I want files from working directory, let the normal Apache mechanism handle it.
    if (workv) return DECLINED;
    
    
    apr_file_t *workf = NULL;
    
    
    // char *pi = r->path_info == NULL || 0 == strlen(r->path_info) ? r->uri : r->path_info;
    const char *docroot = gdc->path == NULL || gdc->location ? ap_context_document_root(r) : gdc->path;
    const char *rp = docroot; // gdc->repo_path
    const char *pi;
    if (gdc->location) {
        pi = r->uri + strlen(gdc->path); }
    else {
        pi = r->filename + strlen(docroot);
    }
    
    while(*pi == '/') pi++;
    
    if (workv) {
/*      if (r->finfo.filetype == APR_NOFILE) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(01233)
        "File does not exist: %s", r->filename);
        return HTTP_NOT_FOUND;
      }
 */
        
        char *fnam = apr_pstrcat( r->pool, rp, "/", pi, NULL);
      if ((rv = apr_file_open(&workf, fnam, APR_READ, APR_OS_DEFAULT, r->pool)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01234)
        "file permissions deny server access: %s", r->filename);
        return HTTP_FORBIDDEN;
      }
    }
    
    if (!r->header_only) {
        conn_rec *c = r->connection;
        apr_bucket_brigade *bb;
        apr_bucket *b;

        bb = apr_brigade_create(r->pool, c->bucket_alloc);
        
        if (workv) {
            ap_update_mtime(r, r->finfo.mtime);
            ap_set_last_modified(r);
            apr_brigade_insert_file(bb, workf, 0, r->finfo.size, r->pool);
            ap_set_etag(r);
        } else {
            if (gdc->repo == NULL) {
                git_repository *repo;
                if (rp == NULL) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01235)
                                  "git handler has no GitRepo path defined");
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                int n = git_repository_open(&repo, rp);
                    if (n!=0) {
                        const git_error *ge = giterr_last();
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(09039)
                                      "git_repository_open failed for %s: %s", rp, ge->message);
                        return HTTP_INTERNAL_SERVER_ERROR;
                    }
                    else {
                        gdc-> repo = repo;
                    }
                }
    
            const char *tv = tag;
            if ( commit != NULL) tv = commit;

            asset *asn = getAsset( gdc->repo, tv, pi );

            if (asn == NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(01233)
                              "File '%s' does not exist in vursion '%s'", r->filename, tag);
                    return HTTP_NOT_FOUND;
            }
            if (commit == NULL) {
                ap_cookie_write(r, "git-commit", asn->commit_id, "path=/", ONE_YEAR, r->headers_out, NULL);
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
                          "mod_git: ap_pass_brigade failed for file %s", r->filename);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    else {
        if (workv) { apr_file_close(workf); }
    }
    
    return OK; // OK is ambiguous -- should be 0
}


static void register_hooks(apr_pool_t *p) {
    ap_hook_handler(git_handler,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_child_init(git_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    git_threads_init();
}

static const char *init_git_config(cmd_parms *cmd, void *dconf, const char *dv) {
    struct git_dir_config *gdc = (struct git_dir_config *)dconf;
//    gdc->repo_path = apr_pstrdup(cmd->pool ,rep);
    gdc->default_vursion = apr_pstrdup(cmd->pool, dv);
    gdc->path = cmd->path == NULL || 0 == strlen(cmd->path) ? NULL : apr_pstrdup(cmd->pool, cmd->path);
    gdc->location = 0;
    if (NULL == cmd->directive->parent) {
        // this means server level config
        return NULL;
    }
    const char *parent = cmd->directive->parent->directive;
    if (0 == strcasecmp("<Location", parent)) {
        gdc->location = 1;
    }
    if (0 == strcasecmp("<LocationMath", parent)) {
        return "Git in LocationMatch stanza not supported";
    }
    
/*
    if (0 == strcasecmp("<Directory", parent)) {
        return "Git configuration should be in a Location, not a Directory";
    }
 */
    return NULL;
}

static void *create_git_dir_config(apr_pool_t *pool, char *d) {
    struct git_dir_config *n = (struct git_dir_config *)apr_pcalloc(pool, sizeof(struct git_dir_config));
    n->default_vursion = "-";
    return n;
}

/*
 static void *merge_git_dir_config(apr_pool_t* pool, void *base, void *add) {
    struct git_dir_config *n = create_git_dir_config(pool, NULL);
    struct git_dir_config *na = add;
    n->repo = na -> repo;
    n->repo_path = na->repo_path == NULL ? NULL : apr_pstrdup(pool, na->repo_path);
    n->default_vursion = na->repo_path == NULL ? NULL : apr_pstrdup(pool, na->default_vursion);
    return add;
}
*/

static const command_rec git_cmds[] = {
    AP_INIT_TAKE1("GitBranch", init_git_config, NULL, RSRC_CONF|ACCESS_CONF, "Git default branch"),
    {NULL}
};

AP_DECLARE_MODULE(git) = {
    STANDARD20_MODULE_STUFF,
    create_git_dir_config,              /* create per-directory config structure */
//    merge_git_dir_config,              /* merge per-directory config structures */
    NULL,
    NULL,              /* create per-server config structure */
    NULL,              /* merge per-server config structures */
    git_cmds,              /* command apr_table_t */
    register_hooks     /* register hooks */
};

