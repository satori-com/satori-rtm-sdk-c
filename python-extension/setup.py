from distutils.core import setup, Extension

crtm = Extension(
    'crtm',
    sources = ['crtm.c',
        '../core/src/rtm.c',
        '../core/src/rtm_posix.c',
        '../easy/rtm_easy.c',
        '../core/src/rtm_json.c'],
    include_dirs = ['../vendor', '../core/src', '../easy'])

setup(name = 'crtm',
      version = '0.1.0',
      description = 'An example of embedding rtm to C',
      ext_modules = [crtm])