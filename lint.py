#!/usr/bin/env python3

import json
import os
import re
import subprocess
import sys

re_I = re.compile(r'-I[/\.\w-]+')
re_Isys = re.compile(r'-isystem [/\.\w-]+')

# TODO: fix relevant warnings and delete items from this list
disabled_checks = [
    'clang-analyzer-alpha.core.CastToStruct',
    'clang-analyzer-alpha.core.PointerArithm',
    'clang-analyzer-alpha.security.ArrayBound',
    'clang-analyzer-alpha.security.ArrayBoundV2',
    'clang-analyzer-alpha.unix.Stream',
    'cppcoreguidelines-pro-bounds-array-to-pointer-decay',
    'cppcoreguidelines-pro-type-vararg',
    'google-build-using-namespace',
    'google-default-arguments',
    'google-readability-braces-around-statements',
    'google-readability-casting',
    'google-readability-todo',
    'google-runtime-references',
    'readability-braces-around-statements',
    'readability-container-size-empty',
    'readability-else-after-return',
    'readability-implicit-bool-cast',
    'readability-inconsistent-declaration-parameter-name',
    'readability-redundant-string-init',
    'readability-simplify-boolean-expr',
    'llvm-include-order']

def main():
    system_includes = get_system_includes()
    db = {}

    dir = 'build-lint'
    if not os.path.exists(dir):
       os.mkdir(dir)
    os.chdir(dir)

    cmake_defines = [
        '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
        '-Dsamples=ON',
        '-Dperf=ON',
        '-Dtest=ON',
        '-Dbench=ON',
        '-DCMAKE_BUILD_TYPE=Release']
    cmake_defines += [a for a in sys.argv if a.startswith('-D')]
    subprocess.check_call(['cmake'] + cmake_defines + ['..'])

    subprocess.check_call(['make'])

    with open('compile_commands.json') as f:
        raw_db = json.load(f)
        for item in raw_db:
            if '/vendor/' in item['file']:
                continue
            db[item['file']] = extract_include_paths(item)

    has_errors = False
    for f in db:
        print('\nLINT', f)
        checks = '-checks=' + ',-'.join(['*'] + disabled_checks)
        if f.endswith('.c'):
            checks += ',-misc-unused-parameters'
        cmd = ['clang-tidy', checks, f, '--']
        cmd += sys.argv[1:]
        if f.endswith('.c'):
            cmd.append('-std=gnu89')
        else:
            cmd.append('-std=c++11')
        cmd += db[f] + system_includes

        try:
            output = subprocess.check_output(cmd).decode("utf-8")
            print(output)
            has_errors = has_errors or (0 < output.find(" error: "))
        except CalledProcessError as ex:
            has_errors = True
            print('Lint returned non-zero exit status: ' + ex.returncode)
            print(ex.output)

    sys.exit(int(has_errors))


def extract_include_paths(item):
    command = item['command']
    return re_I.findall(command) + sum([x.split(' ') for x in re_Isys.findall(command)], [])


def get_system_includes(lang='c'):
    out = subprocess.check_output(
        'echo "int main(void){}" | clang -xc++ -std=c++11 -o /dev/null --verbose /dev/stdin 2>&1 | grep -v ignoring | grep "/include"', shell=True)
    return [b'-isystem' + i.strip() for i in out.split(b'\n') if i.strip()]


if __name__ == '__main__':
    main()
