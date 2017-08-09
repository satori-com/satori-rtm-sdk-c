#!/usr/bin/env python3

import os
import re
import subprocess
import sys

re_I = re.compile(r'-I[/\.\w-]+')
re_Isys = re.compile(r'-isystem [/\.\w-]+')

# TODO: fix relevant warnings and delete items from this list
disabled_checks = [
    'cert-err58-cpp',
    'cert-msc30-c',
    'cert-msc30-cpp',
    'cert-msc50-cpp',
    'clang-analyzer-alpha.core.CastToStruct',
    'clang-analyzer-alpha.core.PointerArithm',
    'clang-analyzer-alpha.security.ArrayBound',
    'clang-analyzer-alpha.security.ArrayBoundV2',
    'clang-analyzer-alpha.unix.Stream',
    'clang-analyzer-nullability.NullableDereferenced',
    'clang-analyzer-nullability.NullPassedToNonnull',
    'clang-analyzer-nullability.NullablePassedToNonnull',
    'clang-analyzer-nullability.NullReturnedFromNonnull',
    'clang-analyzer-security.insecureAPI.rand',
    'clang-analyzer-security.insecureAPI.strcpy',
    'clang-analyzer-unix.Malloc',
    'cppcoreguidelines-no-malloc',
    'cppcoreguidelines-pro-bounds-pointer-arithmetic',
    'cppcoreguidelines-pro-bounds-array-to-pointer-decay',
    'cppcoreguidelines-pro-type-cstyle-cast',
    'cppcoreguidelines-pro-type-vararg',
    'cppcoreguidelines-special-member-functions',
    'google-build-using-namespace',
    'google-default-arguments',
    'google-readability-braces-around-statements',
    'google-readability-casting',
    'google-readability-todo',
    'google-runtime-references',
    'misc-misplaced-widening-cast',
    'misc-unused-parameters',
    'modernize-deprecated-headers',
    'modernize-use-auto',
    'modernize-use-bool-literals',
    'modernize-use-equals-default',
    'modernize-use-equals-delete',
    'modernize-use-nullptr',
    'readability-braces-around-statements',
    'readability-container-size-empty',
    'readability-else-after-return',
    'readability-implicit-bool-cast',
    'readability-inconsistent-declaration-parameter-name',
    'readability-redundant-string-init',
    'readability-redundant-declaration',
    'readability-simplify-boolean-expr',
    'llvm-include-order']

def main():

    dir = 'build-lint'
    if not os.path.exists(dir):
       os.mkdir(dir)
    os.chdir(dir)

    cmake_defines = [
        '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
        '-DEXAMPLES=ON',
        '-DPERF=ON',
        '-DTESTS=ON',
        '-DBENCH=ON',
        '-DCMAKE_BUILD_TYPE=Release']
    cmake_defines += [a for a in sys.argv if a.startswith('-D')]
    check_spec = ',-'.join(['*'] + disabled_checks)
    subprocess.check_call(
        ['cmake',
         "-DCMAKE_C_CLANG_TIDY:STRING=clang-tidy;-checks=" + check_spec,
         "-DCMAKE_CXX_CLANG_TIDY:STRING=clang-tidy;-checks=" + check_spec]
        + cmake_defines
        + ['..'])

    subprocess.check_call(['cmake', '--build', '.'])


if __name__ == '__main__':
    main()
