# ReMusic 0.1.1
Cookie-based sign-in for old YouTube Music (3.47.4, iOS 10), reusing TubeReplacer's sign-in code
(https://github.com/Preloading/TubeReplacer by Preloading, GPLv3). This project is GPLv3 too.

Sign-in hooks come from TubeReplacer. 0.1.1 adds a diagnostics module (ReMusicDiag.m) that writes, into the
Music app's Documents folder (next to TubeReplacer.log):

- ReMusic-methods.txt : method and ivar list of the networking classes (written about 6 seconds after launch)
- ReMusic-diag.log    : every network request the app makes plus a trace of calls into the InnerTube/gRPC
                        request classes. Overwritten at each launch. Cookie and Authorization values are
                        never written, only their names.
- ReMusic-trace.disabled : created automatically if tracing ever crashed the app. Delete it (and
                        ReMusic-trace.pending) to switch tracing back on.
