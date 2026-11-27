# ReMusic 0.1.4
Cookie-based sign-in for old YouTube Music (3.47.4, iOS 10), reusing TubeReplacer's sign-in code
(https://github.com/Preloading/TubeReplacer by Preloading, GPLv3). This project is GPLv3 too.

Sign-in hooks come from TubeReplacer. 0.1.1 added a diagnostics module (ReMusicDiag.m) that writes, into the
Music app's Documents folder (next to TubeReplacer.log):

- ReMusic-methods.txt : method and ivar list of the networking classes (written about 6 seconds after launch)
- ReMusic-diag.log    : every network request the app makes plus a trace of calls into the InnerTube/gRPC
                        request classes. Overwritten at each launch. Cookie and Authorization values are
                        never written, only their names.
- ReMusic-trace.disabled : created automatically if tracing ever crashed the app. Delete it (and
                        ReMusic-trace.pending) to switch tracing back on.

0.1.2: after reinstalling Music, iOS keeps the old saved login while the app's own data is gone, which made
Music flash sign-in errors. If Music's Documents folder has no ReMusic-session.marker, the stored accounts are
forgotten once at launch (and the marker is written), so you can sign in cleanly. To force it again, create an
empty file called ReMusic-reset in the same folder. Tracing is skipped on that first launch.

0.1.3: with nobody signed in, Music asks YouTube for the account list as soon as it opens, gets "400 Precondition
check failed" and asks again about five times a second (this made the sign-in error flash). That one request is
now answered locally with an empty list when it carries no sign-in (ReMusic-fix.disabled is created if the fix
ever crashes the app). The log also shows who made each request (BACKTRACE lines), block signatures, and no
longer fills up with repeats.

0.1.4: every signed-in request (browse, search, library...) was failing inside the app with com.google.sso -214
before it left the iPad, because Music's token wrapper (SSOAuthorizationImpl) wants a Google OAuth access token that
this cookie sign-in cannot provide. That wrapper now authorizes requests with the signed-in account's cookies and a
SAPISIDHASH header instead, as TubeReplacer does for the YouTube app. A copy of the account's cookie fields is also
kept in the keychain (service ReMusic.account) in case the sign-in library does not hand them back after a
relaunch; the fresh-install reset removes it. ReMusic-diag.log shows the server's answer (HTTP status) to each
request, so it shows whether YouTube accepts requests authorized this way.
