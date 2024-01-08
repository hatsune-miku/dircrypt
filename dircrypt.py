#!python3
#encoding:utf-8

import os
import argparse
import uuid
import base64
import logging
import shutil
from typing import Optional


### === Utils ===

def is_windows() -> bool:
    return os.name == 'nt'


def dir_can_write(directory: str) -> bool:
    return os.access(directory, os.W_OK)


def get_logger() -> logging.Logger:
    logger = logging.getLogger('dircrypt')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(name)s %(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def is_valid_dirname(dirname: str) -> bool:
    if dirname.startswith('.'):
        return False
    if dirname == '$RECYCLE.BIN':
        return False
    return True


def directory_list_recursive(path: str):
    """
    Yields (absolute path, folder)s.
    """
    for root, _, filenames in os.walk(path):
        for f in filenames:
            yield (
                os.path.join(root, f).removeprefix(f"{path}/"),
                root
            )


### === Classes ===

class HashUtils:
    @staticmethod
    def base64_encode(s: str) -> str:
        return base64.b64encode(s.encode('utf-8')).decode('utf-8')


    @staticmethod
    def base64_decode(s: str) -> str:
        return base64.b64decode(s.encode('utf-8')).decode('utf-8')


    @staticmethod
    def uuid() -> str:
        return str(uuid.uuid4())


class Metadata:
    def __init__(self):
        self._reverse_names = {}


    def set(self, hash_name: str, real_name: str) -> None:
        self._reverse_names[hash_name] = real_name


    def get(self, hash_name: str) -> Optional[str]:
        return self._reverse_names.get(hash_name)


    def contains_hash(self, hash_name: str) -> bool:
        return hash_name in self._reverse_names


    def  __contains__(self, hash_name: str) -> bool:
        return self.contains_hash(hash_name)


    def __getitem__(self, hash_name: str) -> Optional[str]:
        return self.get(hash_name)


    def __setitem__(self, hash_name: str, real_name: str) -> None:
        self.set(hash_name, real_name)


    def __len__(self) -> int:
        return len(self._reverse_names)


    def __iter__(self):
        yield from self._reverse_names.items()


    def __str__(self) -> str:
        return '\n'.join(
            [': '.join([h, r]) for h, r in self._reverse_names.items()]
        )


    def save(self, file_path: str) -> None:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("DCMETA\n\n")
            f.write("DON'T RENAME, MOVE OR MODIFY ANY FILE IN THIS DIRECTORY "
                    "OR ALL DATA WILL BE LOST\n")
            f.write("切勿删、改、移动此目录下的任何文件，否则所有数据将丢失\n\n")
            for hash_name, real_name in self._reverse_names.items():
                map_string = ':'.join([hash_name, real_name])
                map_string = HashUtils.base64_encode(map_string)
                map_string = '~' + map_string
                f.write(map_string + '\n')


    @staticmethod
    def parse(file_path: str) -> 'Metadata':
        ret = Metadata()

        with open(file_path, 'r', encoding='utf-8') as f:
            lines = list(map(str.strip, f.readlines()))
            if len(lines) == 0:
                raise ValueError('Metadata file is empty or unreadable.')

            first_line = lines.pop(0)
            if first_line != 'DCMETA':
                raise ValueError('Metadata file is not a DCMETA file.')

            for line in lines:
                if not line.startswith('~'):
                    continue

                map_string = HashUtils.base64_decode(line[1:])
                map_string = map_string.split(':')
                if len(map_string) != 2:
                    raise ValueError('Metadata file is corrupted.')

                hash_name, real_name = map_string
                ret.set(hash_name, real_name)
        return ret


class DirectoryEncryptor:
    def __init__(self, logger: logging.Logger, root: str, suffix: str, encrypt_header: bool):
        self.logger = logger
        self.root = root
        self.suffix = suffix
        self.encrypt_header = encrypt_header

        if os.path.exists(os.path.join(root, 'DCMETA.txt')):
            self.metadata = self.read_metadata(root)
            self.mode = 'decrypt'
            self.paths = None
            self.folders = None
        else:
            self.metadata = Metadata()
            self.mode = 'encrypt'
            self.paths = []
            self.folders = []
            for path, folder in directory_list_recursive(root):
                self.paths.append(path)
                if folder != self.root:
                    self.folders.append(folder)
            print(self.folders)


    def get_mode(self) -> str:
        """
        Returns 'encrypt' or 'decrypt'.
        """
        return self.mode


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
        for hashed_path, real_path in self.metadata:
            hashed_path = os.path.join(self.root, hashed_path)
            real_path = os.path.join(self.root, real_path)
            dirname = os.path.dirname(real_path)
            if dirname != '':
                os.makedirs(dirname, exist_ok=True)
            if os.path.exists(hashed_path):
                shutil.move(hashed_path, real_path)
                if self.encrypt_header:
                    self._obfuscate_header(real_path)
                self.logger.info(
                    f"{hashed_path} -> {real_path}" + 
                    (' (Decrypt Header)' if self.encrypt_header else '')
                )
            else:
                self.logger.warning(f"Missing file: {hashed_path}")

        self.logger.info('Removing metadata...')
        os.remove(os.path.join(self.root, 'DCMETA.txt'))
        shutil.rmtree(os.path.join(self.root, 'DCDATA'), ignore_errors=True)


    def write_metadata_and_encrypt(self) -> None:
        self.logger.info('Encrypting...')
        os.makedirs(os.path.join(self.root, 'DCDATA'), exist_ok=True)
        metadata = Metadata()
        for path in self.paths:
            hashed_path = HashUtils.uuid() + self.suffix
            hashed_path_relative = os.path.join('DCDATA', hashed_path)
            hashed_path = os.path.join(self.root, hashed_path_relative)
            shutil.move(
                os.path.join(self.root, path),
                hashed_path
            )

            if self.encrypt_header:
                self._obfuscate_header(hashed_path)
            self.logger.info(
                f"{path} -> {hashed_path}" + 
                (' (Encrypt Header)' if self.encrypt_header else '')
            )

            metadata.set(hashed_path_relative, path)
        metadata.save(os.path.join(self.root, 'DCMETA.txt'))

        self.logger.info('Removing old directories...')
        for folder in self.folders:
            self.logger.info(f"Removing {folder}...")
            shutil.rmtree(folder, ignore_errors=True)

    @classmethod
    def read_metadata(cls, path: str) -> Optional[Metadata]:
        meta_path = os.path.join(path, 'DCMETA.txt')
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
        print(f"Error: Directory '{args.path}' is not writable.")
        return

    logger = get_logger()
    logger.info('Building directory map...')

    encryptor = DirectoryEncryptor(
        logger=logger,
        root=args.path,
        suffix=args.suffix,
        encrypt_header=args.encrypt_header
    )
    if encryptor.get_mode() == 'decrypt':
        encryptor.restore_from_metadata()
    else:
        encryptor.write_metadata_and_encrypt()
    logger.info('Done!')


if __name__ == '__main__':
    main()
