# -* - coding: UTF-8 -* -
# ! /usr/bin/python

if __name__ == '__main__':
    def split_file(input_file, output_prefix, num_pieces=10):
        with open(input_file, 'r') as infile:
            # Determine the total number of lines in the file
            total_lines = sum(1 for line in infile)

        lines_per_piece = total_lines // num_pieces
        remainder_lines = total_lines % num_pieces

        with open(input_file, 'r') as infile:
            start = 0
            for i in range(num_pieces):
                end = start + lines_per_piece + (1 if i < remainder_lines else 0)

                output_file = f"{output_prefix}_{i + 1}.txt"
                with open(output_file, 'w') as outfile:
                    # Read and write the file in chunks instead of loading it all into memory
                    for line in infile:
                        outfile.write(line)
                        start += 1
                        if start == end:
                            break


    # Example usage:
    import sys
    input_file_path = sys.argv[1]
    # input_file_path = '../detection/system_log0131.txt'
    output_file_prefix = 'log'
    split_file(input_file_path, output_file_prefix, num_pieces=30)