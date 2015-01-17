
mod_git is an Apache module which serves files from a (possibly bare) git repo.  The client specifies, via cookie, which commit to use, and Apache serves the version of the file from that commit.

Configuration is simple.  Include the module by

```
   LoadModule git_module path/to/mod_git.so
```

and activate it by specifying, in either a directory or virtual server

```
   SetHandler git
   GitRepo path-to-repo default-branch-or-tag
```

The document root or directory context is assumed to be the git repository.  The branch or tag being served by default is specified in GitRepo.  Any commitish will do.  Use a dash (`-`) to signify that the default should be the working copy -- in which case files will be served from the file system.

To use from a browser, navigate to the configured directory.  The files you will see will be from the specified branch in the specified repo.  To see a different version, the request must include a cookie `git-tag` containing the commitish desired.  A cookie is used since all of the assets referenced on a page should come from the same commit -- so we wanted a scheme that would include the same commitish on every request.  That would be the cookie.  This should have the following effect:

1.  The file served will be from the specified tag (or branch or commitish).
2.  A response header (`X-Commit`) will be set with the hash from the resolved commit.

Specifying a value of "-" (or an empty value) will serve the checked out working version from the file system.

Cookie values like `testing@{3 hours ago}` should work.

A common use case is to have a github hook fire which causes your web server to `git fetch` every time you push to github.  That way, your deployment strategy is "push to github" -- and your changes are visible on your website -- if you are looking at the right branch.  As part of their user profile, users have a "default version" setting -- which sets their `git-tag` cookie to track the appropriate branch (`prod` or `testing` or `beta`).  Each user sees the branch they are tracking.

This is most useful for applications that use Angular or React or other client side frameworks -- such that most of the changes are made to files which are served by Apache.  CGI scripts, for example will not be versioned through this module, since they must be handled by `mod_cgi` instead of `mod_git`.

`mod_git` will set `ETag` to the git hash -- since that should uniquely identify a particularly version, and the `Last-Modified` time will be the time of the commit.

Building
========

You will need `libgit2` (and `apache` of course) installed.

The Xcode project file is included in the repo.

For Linux, the build command is:

```
   apxs -i -c mod_git.c -lgit2
```

History
=======

An earlier version of this module would check query parameters to set the `git-tag` cookie from a query parameter.  This would make it easier for unsophisticated users to switch versions.  However, it was felt that the version switching was more of a development feature, and it would not be unreasonable to expect the people wishing to take advantage of this feature to have an EditCookie extension installed in their browsers to set the cookie to switch versions.

Known Issues
============

- LocationMatch is not supported.
- There is concern that having a client request historical commits might expose security vulnerabilities that had been patched in later commits.  The proposed solution is to have an option to check to ensure that requested versions must be either a defined tag or the HEAD of a branch.  In this way, only "named" commits are available to the web client.  This check is not yet implemented.
- Since the module does not use the Apache directory walk logic to locate files (it uses libgit2), it does not do the .htaccess processing.  It should be possible to copy the logic from  `server/request.c`  to locate and parse `.htaccess` files.  This has not yet been done.

