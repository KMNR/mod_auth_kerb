mod_auth_kerb
=============

Patched version of mod_auth_kerb for communicating with Missouri S&amp;T authentication services


HOWTO Install
=============

Obviously, you need a compiler. The pachage you will be installing is located under /trunk/mod_auth_kerb/mod_auth_kerb-5.4/. Prerequisites for compilation include:

For CentOS
----------

krb5-devel
httpd-devel


For Ubuntu/Debian
-----------------
libkrb5-dev
apache2-threaded-dev

With those installed, you should be able to compile and install.

     $ ./configure --with-krb4=no
     $ make
     $ sudo make install


Source
======

The source code here was grabbed from Missouri S&T's SVN servers. Anyone can download this by installing git-svn and calling:

    $ git svn clone https://svn.mst.edu/project/apache/


Attribution
===========

In the past, KMNR personnel might have had some influence in the creation of this package. However, those personnel were paid by the Missouri S&T/UMR IT department for their work. Now-a-days, KMNR has no influence on this package. We just use it. As such, we provide no guarantee it will work, and will not be held liable if you install it and shit breaks.

Refer to the commit history for appropriate attribution.

