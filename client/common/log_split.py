import os
import sys
from multiprocessing import Pool


def process_chunk(args):
    input_file, output_prefix, start, size, chunk_id = args
    buffer_size = 1024 * 1024  # Read in 1MB chunks to manage memory usage

    output_file = f"{output_prefix}_chunk_{chunk_id}.txt"
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        infile.seek(start)
        remaining = size
        while remaining > 0:
            data = infile.read(min(buffer_size, remaining))
            outfile.write(data)
            remaining -= len(data)


def split_file(input_file, output_prefix, chunk_size_gb=5):
    file_size = os.path.getsize(input_file)
    chunk_size = chunk_size_gb * 1024 ** 3  # Convert GB to bytes

    # Calculate the number of chunks needed
    num_chunks = -(-file_size // chunk_size)  # Ceiling division to ensure all data is covered

    # Create arguments for each chunk
    args = [(input_file, output_prefix, i * chunk_size, min(chunk_size, file_size - (i * chunk_size)), i) for i in
            range(num_chunks)]

    # Use multiprocessing to process chunks in parallel
    with Pool() as pool:
        pool.map(process_chunk, args)


if __name__ == '__main__':
    input_file_path = sys.argv[1]
    out_file_path = sys.argv[2]
    output_file_prefix = os.path.join(out_file_path, "log_split")
    split_file(input_file_path, output_file_prefix)