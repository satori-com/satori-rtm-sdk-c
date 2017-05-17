
AC_INIT([librtm], [1.0], [satori@mz.com])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])

AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_AR

AC_ARG_ENABLE(apple-ssl,
  [  --enable-apple-ssl  Use Apple SSL],
  [ enable_apple_ssl=yes])
AM_CONDITIONAL([ENABLE_APPLE_SSL], [test $enable_apple_ssl = yes])

AC_ARG_ENABLE(open-ssl,
  [  --enable-open-ssl  Use OpenSSL],
  [ enable_open_ssl=yes])
AM_CONDITIONAL([ENABLE_OPEN_SSL], [test $enable_open_ssl = yes])

dnl C flags
RTM_CPPFLAGS="-Ivendor -Icore/src -Ieasy"
test $enable_apple_ssl = yes && {
	RTM_CPPFLAGS="${RTM_CPPFLAGS} -DUSE_APPLE_SSL=ON"
}
test $enable_open_ssl = yes && {
	RTM_CPPFLAGS="${RTM_CPPFLAGS} -DUSE_OPENSSL=ON"
}
AC_SUBST(RTM_CPPFLAGS)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
