# S3 Content-Addressable Storage

Store files in S3 indexed by their SHA256 hash instead of by filename.

```text
$ echo 'Hello World!' > foo
$ cp foo foo2
$ cat test.py
import s3_cas
c = s3_cas.S3CasClient("my-bucket", "blobs")
c.upload_file("foo")
c.upload_file("foo2")
$ python test.py
INFO:s3cas:Uploaded file to s3://my-bucket/blobs/03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340
INFO:s3cas:File already exists with hash 03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340, name foo, not uploading.
```
