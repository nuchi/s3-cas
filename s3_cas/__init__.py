import hashlib
import logging
import os

import boto3
from botocore.exceptions import ClientError


class S3CasClient:
    FILENAME_KEY = 'filename'
    HASH_FN = hashlib.sha256

    def __init__(self, bucket, prefix=None, client=None, debug=True):
        """
        A content-addressable storage interface to an s3 bucket.
        :param bucket: the name of the s3 bucket to use as the backing store
        :param prefix: a subdirectory in the bucket (optional)
        :param client: an optional s3 client (one will be created if not passed)
        :param debug: whether to print debug info
        """
        self.client = client or boto3.client('s3')
        self.bucket = bucket
        self.prefix = prefix
        self.debug = debug
        if debug:
            self.logger = logging.getLogger('s3cas')
            logging.basicConfig()
            self.logger.setLevel(logging.INFO)

    def _hash_file(self, file_name):
        h = self.HASH_FN()
        buf_size = 65536
        with open(file_name, 'rb') as f:
            while True:
                data = f.read(buf_size)
                if not data:
                    break
                h.update(data)
        return h.hexdigest()

    def _object_name(self, object_hash):
        if self.prefix is None:
            return object_hash
        return f'{self.prefix}/{object_hash}'

    def _get_existing_filename(self, object_name):
        try:
            return self.client.head_object(Bucket=self.bucket, Key=object_name)['Metadata'][self.FILENAME_KEY]
        except (ClientError, KeyError, TypeError):
            return None

    def _log(self, s):
        if not self.debug:
            return
        self.logger.info(s)

    def upload_file(self, file_name):
        """
        Upload a file to the backing store and index by hash, storing the filename in metadata.
        Skips uploading if it's already present.
        :param file_name: the name of the local file
        :return: the hash of the stored file
        """
        object_hash = self._hash_file(file_name)
        object_name = self._object_name(object_hash)
        existing_filename = self._get_existing_filename(object_name)
        if existing_filename is not None:
            self._log(f'File already exists with hash {object_hash}, name {existing_filename}, not uploading.')
        else:
            m_filename = os.path.basename(file_name)
            self.client.upload_file(file_name, self.bucket, object_name, ExtraArgs={'Metadata': {self.FILENAME_KEY: m_filename}})
            self._log(f'Uploaded file to s3://{self.bucket}/{object_name}')
        return object_hash

    def download_file(self, object_hash, download_dir=None, file_name=None):
        """
        Download a file indexed by hash. At least one of `download_dir` or `file_name` must be present.
        If only the download_dir parameter is present, then the file's metadata is used to determine
        the file name.
        :param object_hash: the object's hash
        :param download_dir: the directory to download to
        :param file_name: the file name to download to
        :return: the filename of the downloaded file, or None if there was an existing file at that name with
            a different hash.
        """
        if download_dir is None and file_name is None:
            raise ValueError('At least download_dir or file_name must be specified.')

        object_name = self._object_name(object_hash)
        existing_filename = self._get_existing_filename(object_name)
        if existing_filename is None:
            raise KeyError(f'No file found with hash {object_hash}')

        if file_name is None:
            download_to = os.path.join(download_dir, existing_filename)
        elif download_dir is None:
            download_to = file_name
        else:
            download_to = os.path.join(download_dir, file_name)

        if not os.path.exists(download_to):
            print(self.bucket, object_name, download_to)
            self.client.download_file(Bucket=self.bucket, Key=object_name, Filename=download_to)
            self._log(f'Downloaded file to {download_to}')
        elif self._hash_file(download_to) == object_hash:
            self._log(f'File with correct hash already exists at {download_to}')
        else:
            self._log(f'Not overwriting existing file with different hash at {download_to}')
            return None

        return download_to
