# utils.py

import hashlib
import sys


def chunk_size(size, text):
    """
    Generates a block of data, incrementing till the EOF
    :param size: Size of block in bytes
    :param text: Text of file being chunked
    :return: A chunk of data of the size of the block, or smaller if at EOF
    """
    start = 0
    while start < len(text):
        chunk = text[start: start + size]
        yield chunk
        start += size
    return


def hash_file(file, alg):
    """
    Generates a Hash for file, once it has been chunked and added to the buffer.
    :param alg: Hashing algorithm to be used
    :param file: File passed in to be hashed
    :return: returns a  hash of file
    """
    # sets a block size limit to be hashed
    block_size = 4000
    if alg is None:
        raise KeyError("No hashing algorithm selected.")
    elif alg.lower() == "md5":
        # MD5 hash buffer for each block of data held in memory
        hash_buffer = hashlib.md5()
    elif alg.lower() == "sha1":
        # SHA1 hash buffer for each block of data held in memory
        hash_buffer = hashlib.sha1()
    else:
        # SHA256 hash buffer for each block of data held in memory
        hash_buffer = hashlib.sha256()

    try:
        # Read in file
        with open(file, "rb") as binFile:
            # For each chunk of data returned from chunk_size
            for chunk in chunk_size(block_size, binFile.read()):
                # Add it to the buffer
                hash_buffer.update(chunk)
            # Run a md5 hash on the entire file in the buffer, and return
            return hash_buffer.hexdigest().encode("utf-8")
    except MemoryError as e:
        # If MemoryError, virtual memory depleted.  May need to add more memory, or choose a smaller file.
        print("Exception: {}".format(str(e)))
        sys.exit(1)
    except Exception as e:
        print("Exception: {}".format(str(e)))
