# Security Policy

To get help, the BackupPC Users' Mailing List is the starting point.

BackupPC is supported by G.W. Haywood.  It is July 2026.  Mr. Haywood
has undertaken to provide support so long as he is physically able to
do so.  Even if we assume continuation of his remarkably good health,
realistically that means at most 20 years more support (i.e., in case
you're wondering about his levels of commitment, about half the length
of time that he has devoted to supporting his "Sales Office System").

There are effectively three parts to the BackupPC software:

* BackupPC		Perl scripts which hav overall control of backups.
* BackupPC_XS	Supporting Perl/XS modules written in C for performance.
* rsync-bpc		A fork of the famous 'rsync', for use only by BackuppC.

Issues for each part are tracked separately.  Each may be subject to
its own set of security issues but the way in which these are handled
is in all cases much the same.

BackupPC version numbers have three parts, e.g. "4.4.0".  Historically
they have been updated when major changes have been made, for example
to the functionality or the underlying storage techniques.  It is now
considered that, in the foreseeable future, large changes are unlikely
to be made.  In all probability future releases will be point releases
that increment only the last integer.

BackupPC-XS version numbers have two parts, for example "0.62".  Until
further notice they will increment to "0.63", "0.64", ...

Because rsync-bpc is effectively a fork of rsync, an rsync-bpc version
number is taken from the version of rsync on which it is based with an
extra '.N' ('N' is just an integer) added to track changes in the code
after the fork.

In all cases 'release candidate' status may be indicated by the suffix
'rcn' (n is a single digit) immediately after the version number, for
example "BackupPC-4.4.1rc1".

RELEASES OF BackupPC MAY NOT NECESSARILY BE PUBLISHED ON GITHUB.


## Supported Versions

Actively supported versions are the most recent point release and the
previous release plus any release candidate.  As of July 2026 these are:

* BackupPC - 4.4.0, 4.4.1rc1
* BackupPC_XS - 0.62, 0.63rc1, 0.63rc2
* rsync-bpc - 3.1.3.x, 3.4.1.0rc1

(x = any integer)

In addition, rsync-bpc version 3.1.2.x will be supported on a
'best-effort' basis.

If you need help porting code such as security fixes to older
releases, please ask for it on the BackupPC Users' Mailing List:

https://sourceforge.net/p/backuppc/mailman/backuppc-users/


## Reporting a security issue

If you have found an issue that you think may have implications for
security, please in the first instance post a message to the Users'
Mailing List.

Please only post to this public list the fact that you have found an
issue - please do not post technical details about the issue itself,
because they might be useful to malicious actors.

The maintainer will contact you privately by email to discuss the
follow-up action needed.


G.W. Haywood <backup@jubileegroup.co.uk>
Maintainer, BackupPC.
21 July 2026.
