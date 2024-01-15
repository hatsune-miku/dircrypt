#!python3
#encoding:utf-8

"""
dircrypt.py

Encrypts & decrypts directories. Blazing fast!

Naming Conventions:
    - hashed: The renamed file
"""

import os
import argparse
import uuid
import base64
import logging
import shutil
import time
from typing import Optional


### === Global definitions ===

PATH_SEPERATOR = '*'
IS_WINDOWS = os.name == 'nt'


### === Utils ===


def pause():
    input("Press the <ENTER> key to continue...")


def dir_can_write(directory: str) -> bool:
    return os.access(directory, os.W_OK)


def get_logger() -> logging.Logger:
    logger = logging.getLogger('dircrypt')
    file_logger = logging.getLogger('dircrypt-verbose')

    logger.setLevel(logging.DEBUG)
    file_logger.setLevel(logging.DEBUG)

    logger_handler = logging.StreamHandler()
    file_handler = logging.FileHandler('dircrypt.log', encoding='utf-8')

    formatter = logging.Formatter(
        "%(name)s %(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S")
    logger_handler.setFormatter(formatter)
    logger.addHandler(logger_handler)
    file_logger.addHandler(file_handler)
    return logger, file_logger


def normalize_path(path: str) -> str:
    """
    Normalizes a path by unifying the seperator to `/`.
    """
    if IS_WINDOWS:
        return path.replace('\\', '/')
    return path


def join_path(root: str, path: str) -> str:
    """
    `os.path.join` but always uses `/` as seperator.
    """
    return normalize_path(os.path.join(root, path))


def is_valid_dirname(dirname: str) -> bool:
    if dirname.startswith('.'):
        return False
    return dirname not in ['System Volume Information', 'DCDATA', '$RECYCLE.BIN']


def is_valid_filename(filename: str) -> bool:
    if filename.startswith('.'):
        return False
    return filename not in ['desktop.ini', 'Thumbs.db', 'thumbs.db']


def directory_list_recursive(path: str):
    """
    Yields (absolute path, folder)s.
    """
    for root, _, filenames in os.walk(path):
        for f in filenames:
            if not is_valid_filename(f):
                continue
            
            yield (
                join_path(root, f).removeprefix(f"{path}/"),
                normalize_path(root)
            )


### === Classes ===

class HashUtils:
    uid_sequence = 0

    @staticmethod
    def base64_encode(s: str) -> str:
        return base64.b64encode(s.encode('utf-8')).decode('utf-8')


    @staticmethod
    def base64_decode(s: str) -> str:
        return base64.b64decode(s.encode('utf-8')).decode('utf-8')


    @classmethod
    def uid(cls) -> str:
        cls.uid_sequence += 1
        return f"{uuid.uuid4()}-{cls.uid_sequence}"


class Metadata:
    def __init__(self):
        self.hash_to_real = {}


    def set(self, hash_name: str, real_name: str) -> None:
        self.hash_to_real[hash_name] = real_name


    def get(self, hash_name: str) -> Optional[str]:
        return self.hash_to_real.get(hash_name)


    def contains_hash(self, hash_name: str) -> bool:
        return hash_name in self.hash_to_real


    def  __contains__(self, hash_name: str) -> bool:
        return self.contains_hash(hash_name)


    def __getitem__(self, hash_name: str) -> Optional[str]:
        return self.get(hash_name)


    def __setitem__(self, hash_name: str, real_name: str) -> None:
        self.set(hash_name, real_name)


    def __len__(self) -> int:
        return len(self.hash_to_real)


    def __iter__(self):
        yield from self.hash_to_real.items()


    def __str__(self) -> str:
        return '\n'.join(
            [': '.join([h, r]) for h, r in self.hash_to_real.items()]
        )


    def save(self, file_path: str) -> None:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("DCMETA\n\n")
            f.write("DON'T RENAME, MOVE OR MODIFY ANY FILE IN THIS DIRECTORY "
                    "OR ALL DATA WILL BE LOST\n")
            f.write("切勿删、改、移动此目录下的任何文件，否则所有数据将丢失\n\n")
            for hash_name, real_name in self.hash_to_real.items():
                map_string = PATH_SEPERATOR.join([hash_name, real_name])
                map_string = HashUtils.base64_encode(map_string)
                map_string = '~' + map_string
                f.write(map_string + '\n')


    @staticmethod
    def parse(file_path: str) -> 'Metadata':
        ret = Metadata()

        with open(file_path, 'r', encoding='utf-8') as f:
            lines = list(map(str.strip, f.readlines()))
            if len(lines) == 0:
                raise ValueError("Metadata file is empty or unreadable.")

            first_line = lines.pop(0)
            if first_line != 'DCMETA':
                raise ValueError("Metadata file is not a DCMETA file.")

            for line in lines:
                if not line.startswith('~'):
                    continue

                map_string = HashUtils.base64_decode(line[1:])
                map_string = map_string.split(PATH_SEPERATOR)
                if len(map_string) != 2:
                    raise ValueError("Metadata file is corrupted.")

                hash_name, real_name = map_string
                ret.set(hash_name, real_name)
        return ret


class DirectoryEncryptor:
    def __init__(
        self,
        logger: logging.Logger,
        file_logger: logging.Logger,
        root: str,
        suffix: str,
        encrypt_header: bool
    ):
        self.logger = logger
        self.file_logger = file_logger
        self.root = normalize_path(root)
        self.suffix = suffix
        self.encrypt_header = encrypt_header

        if os.path.exists(join_path(root, 'DCMETA.txt')):
            self.metadata = self.read_metadata(root)
            self.mode = 'decrypt'
            self.paths = None
            self.folders = None
            self.file_count = len(self.metadata)
        else:
            self.metadata = Metadata()
            self.mode = 'encrypt'
            self.paths = []
            self.folders = []
            for path, folder in directory_list_recursive(root):
                self.paths.append(path)
                if folder != self.root:
                    self.folders.append(folder)
            self.file_count = len(self.paths)


    def get_mode(self) -> str:
        """
        Returns 'encrypt' or 'decrypt'.
        """
        return self.mode


    def count(self) -> int:
        """
        Returns the number of files to be encrypted/decrypted.
        """
        return self.file_count


    def _obfuscate_header(self, path: str) -> None:
        size = os.stat(path).st_size
        if size <= 16:
            return
        with open(path, 'rb+') as f:
            first_bytes = f.read(16)
            first_bytes = [b ^ 0x39 for b in first_bytes]
            f.seek(0)
            f.write(bytes(first_bytes))


    def restore_from_metadata(self) -> None:
        self.logger.info('Existing metadata found.')
        self.logger.info('Restoring...')

        count = len(self.metadata)
        flag_always_do_it = False

        for i, (hashed_path, metadata_path_abs) in enumerate(self.metadata):
            if ((i + 1) % 100 == 0) or (i + 1 == count):
                self.logger.info(f"Decrypting {i + 1}/{count}...")

            should_decrypt = hashed_path.startswith('DCDATA/obfs.')

            # Convert to host path
            hashed_path = join_path(self.root, hashed_path)
            metadata_path_abs = join_path(self.root, metadata_path_abs)
            metadata_path_dir_abs = normalize_path(os.path.dirname(metadata_path_abs))

            # Create the dir if it's not root
            if metadata_path_dir_abs != '':
                os.makedirs(metadata_path_dir_abs, exist_ok=True)

            # Required hash file not found?
            if not os.path.exists(hashed_path):
                self.logger.warning(f"Missing file during restore: {hashed_path}")
                continue

            # Restore the file
            try:
                shutil.move(hashed_path, metadata_path_abs)
            except Exception as e:
                self.logger.warning(f"Failed to restore {hashed_path}. Error is:")
                self.logger.warning(e)
                continue

            # If user specified to decrypt header when they shouldn't
            if should_decrypt != self.encrypt_header:
                if not flag_always_do_it:
                    file_state = 'encrypted' if should_decrypt else 'not encrypted'
                    user_action = 'to decrypt' if self.encrypt_header else 'not to decrypt'

                    self.logger.warning(f"File {hashed_path} appears to be {file_state},")
                    self.logger.warning(f"but user specified {user_action} header.")
                    self.logger.warning("===============================================")
                    self.logger.warning("Doing so may cause the file to be CORRUPTED & UNRECVOVERABLE.")
                    self.logger.warning("If you know exactly what you are doing,")
                    self.logger.warning("Enter 'JUST DO IT' to continue, or")
                    self.logger.warning("Enter 'ALWAYS DO IT' to apply this to all files, or")
                    self.logger.warning("Enter 'SKIP' to skip this file only, or")
                    self.logger.warning("Enter anything else to abort.")
                    self.logger.warning("===============================================")
                    user_input = input('\nInput your choice: ').strip()
                    if user_input == 'ALWAYS DO IT':
                        flag_always_do_it = True
                    elif user_input == 'JUST DO IT':
                        pass
                    elif user_input == 'SKIP':
                        self.logger.warning(f"Skipped - file {hashed_path} is unchanged.")
                        continue
                    else:
                        self.logger.warning(f"Aborted.")
                        return

            if self.encrypt_header:
                try:
                    self._obfuscate_header(metadata_path_abs)
                except Exception as e:
                    self.logger.warning(f"Failed to deobfs header for {metadata_path_abs}:")
                    self.logger.warning(e)
                    continue

            self.file_logger.info(
                f"{hashed_path} -> {metadata_path_abs}" + 
                (' (Decrypt Header)' if self.encrypt_header else '')
            )

        self.logger.info('Removing metadata...')
        try:
            os.remove(join_path(self.root, 'DCMETA.txt'))
            shutil.rmtree(join_path(self.root, 'DCDATA'), ignore_errors=True)
        except:
            self.logger.info("Failed to remove metadata - It's OK")


    def write_metadata_and_encrypt(self) -> None:
        self.logger.info('Encrypting...')

        # Convert to host path
        real_dcdata_path = join_path(self.root, 'DCDATA')
        os.makedirs(real_dcdata_path, exist_ok=True)

        metadata = Metadata()
        count = len(self.paths)

        for i, path in enumerate(self.paths):
            prefix = 'obfs.' if self.encrypt_header else ''
            hashed_path = prefix + HashUtils.uid() + self.suffix
            hashed_path_rel = join_path('DCDATA', hashed_path)
            hashed_path_abs = join_path(self.root, hashed_path_rel)

            if ((i + 1) % 100 == 0) or (i + 1 == count):
                self.logger.info(f"Encrypting {i + 1}/{count}...")

            # Rename the file
            try:
                shutil.move(
                    join_path(self.root, path),
                    hashed_path_abs
                )
            except Exception as e:
                self.logger.warning(f"Failed to encrypt {path}. Error is:")
                self.logger.warning(e)
                continue

            if self.encrypt_header:
                try:
                    self._obfuscate_header(hashed_path_abs)
                except Exception as e:
                    self.logger.warning(f"Failed to obfuscate header for {hashed_path_abs}:")
                    self.logger.warning(e)
                    continue

            self.file_logger.info(
                f"{path} -> {hashed_path_abs}" + 
                (' (Encrypt Header)' if self.encrypt_header else '')
            )
            metadata.set(hashed_path_rel, path)

        self.logger.info('Writing metadata...')
        while True:
            try:
                metadata.save(join_path(self.root, 'DCMETA.txt'))
                break
            except Exception as e:
                self.logger.error("!! Failed to write metadata. Error is:")
                self.logger.error(e)
                self.logger.error("!! METADATA MUST BE WRITABLE, OR ALL DATA WILL BE LOST.")
                self.logger.error("!! dircrypt will try until it succeeds.")
                self.logger.error("Press any key to continue...")
                pause()


        self.logger.info('Removing old directories...')
        for folder in self.folders:
            self.file_logger.info(f"Removing {folder}...")
            try:
                shutil.rmtree(folder, ignore_errors=True)
            except Exception as e:
                self.logger.warning(f"Failed to remove {folder}. Error is:")
                self.logger.warning(e)
                self.logger.warning("It's OK that the folder is not removed.")
                continue

    @classmethod
    def read_metadata(cls, path: str) -> Optional[Metadata]:
        meta_path = join_path(path, 'DCMETA.txt')
        if not os.path.exists(meta_path):
            return None
        return Metadata.parse(meta_path)


    @classmethod
    def print_learn_more(cls) -> None:
        print(
            "Learn More: dircrypt randomly renames files and optionally destroys "
            "their headers to avoid your files from being indexed, "
            "searched or previewed."
        )


def main() -> None:
    logger, file_logger = get_logger()
    parser = argparse.ArgumentParser(
        prog='dircrypt',
        description='Encrypts & decrypts directories. Blazing fast!',
    )
    parser.add_argument('path', nargs='?')
    parser.add_argument('--encrypt-header', default=False, action='store_true')
    parser.add_argument('--learn-more', help='Learn more about dircrypt.', action='store_true')
    parser.add_argument('--suffix', default='')
    args = parser.parse_args()

    if args.learn_more:
        DirectoryEncryptor.print_learn_more()
        return

    if args.path is None:
        parser.print_help()
        return

    if not dir_can_write(args.path):
        logger.info("Error: Directory %s is not writable.", args.path)
        return

    if args.encrypt_header:
        logger.info("Header encryption is enabled. This slows down the process.")


    logger.info('Building directory map...')

    start_time = time.time()

    encryptor = DirectoryEncryptor(
        logger=logger,
        file_logger=file_logger,
        root=args.path,
        suffix=args.suffix,
        encrypt_header=args.encrypt_header
    )

    mode = encryptor.get_mode()
    logger.info("%d files to be %sed.", encryptor.count(), mode)

    if mode == 'decrypt':
        encryptor.restore_from_metadata()
    else:
        encryptor.write_metadata_and_encrypt()

    end_time = time.time()
    logger.info("✨Done in %.2fs", end_time - start_time)


if __name__ == '__main__':
    main()
