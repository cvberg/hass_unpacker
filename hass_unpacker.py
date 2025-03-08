#!/usr/bin/env python3
"""
Decrypt a Home Assistant backup.

The first level of a backup is unencrypted, but the tar.gz files are encrypted.
By adding "all", all files will be unpacked.
If you want to unpack a single tar.gz file, specify that instead of "all".

The files will be unpacked into folders named after the tar files.
Example: "%s path/backup.tar ssl.tar.gz".
Then the "ssl" files will be written to "path/backup/ssl".
Please note that "path/backup/ssl" will be erased before unpacking!

Usage:
  %s path/to/tarfile.tar                  # List the first-level content
  %s path/to/tarfile.tar all              # Unpack all content
  %s path/to/tarfile.tar example.tar.gz   # Unpack a single specified tar.gz file

"""
# Author: Cornelis Vissenberg
# Copyright: (c) 2025 Cornelis Vissenberg
# License: Apache License Version 2.0
#
# A few lines have been copied from the Home Assistant source code.
# Therefor the license is identical to that of Home Assistant.

import os
import sys
import re
import shutil
import getpass
import hashlib
import tarfile
try:
    import securetar #type: ignore
except ImportError:
    print('Make sure you have a Python 3.10+ installation with "securetar" included.\n' \
          'Install it using:\n' \
          '    pip install securetar'
    )
    sys.exit(1)


RE_GZFILE = re.compile(r'^(.+)\.tar\.gz$')
RE_TARFILE = re.compile(r'^(.+)\.tar$')

def fatal(msg: str) -> str:
    """ Print message and exit. """
    if msg is not None:
        print(msg)
        sys.exit(1)
    # Just to make MyPy happy
    return ''


def password_to_key(password: str) -> bytes:
    """Generate a AES Key from password.
    """
    key: bytes = password.encode()
    for _ in range(100):
        key = hashlib.sha256(key).digest()
    return key[:16]


def get_filenames(tar_path: str) -> list[str]:
    """ Return a list of filenames embedded in the tar file.
    """
    try:
        with tarfile.open(tar_path, 'r') as tar:
            filenames = [member.name for member in tar.getmembers() if member.isfile()]
        return filenames
    except FileNotFoundError:
        fatal(f'File {tar_path} does not exist')
        return []


def unpack_tgz(tar_path: str, folder_path: str, password: str) -> None:
    """ Unpack an encrypted tar.gz file.
    """
    print(f'Unpacking {tar_path}', flush=True)
    try:
        shutil.rmtree(folder_path, ignore_errors=True)
        with securetar.SecureTarFile(
            tar_path,
            gzip=True,
            key=password_to_key(password) if password else None,
            mode="r",
        ) as fp:
            fp.extractall( #type: ignore
                path=folder_path,
                members=securetar.secure_path(fp),
                filter="fully_trusted",
            )
    except tarfile.ReadError:
        fatal('Bad content or incorrect password!')


def unpack_nested(tar_path: str, password: str, files: list):
    """ Unpack TAR file and its nested encrypted tar.gz specified in `files`.
    """
    m = RE_TARFILE.search(tar_path)
    folder = m.group(1) if m else fatal('Not a TAR file.')

    for file in files:
        m = RE_GZFILE.search(file)
        subfolder = m.group(1) if m else ''
        if subfolder:
            with tarfile.open(tar_path, 'r') as tar:
                member = tar.getmember(file)
                tar.extract(member, path=folder, filter='data')
            unpack_tgz(os.path.join(folder, file),
                       os.path.join(folder, subfolder), password)
            os.remove(os.path.join(folder, file))


def main() -> None:
    """ Main.
    """
    tar_file = sys.argv[1] if len(sys.argv) > 1 else ''
    arg = sys.argv[2] if len(sys.argv) > 2 else ''

    m = RE_TARFILE.search(tar_file)
    if m:
        files = get_filenames(tar_file)
        if arg == '':
            for file in files:
                print(file)
            print('\nUnpack by adding "all" or a specific tar.gz file name.\n')
        else:
            password = getpass.getpass('Enter your decryption key: (empty for unencrypted)')
            unpack_nested(tar_file, password, files if arg=='all' else [arg])
    else:
        myargs = (os.path.split(sys.argv[0])[1], ) * 4
        print(__doc__ % myargs)
        sys.exit(1)


if __name__ == '__main__':
    main()
