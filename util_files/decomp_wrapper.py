import os
import subprocess
import sys

def decompile_file(unluac_path, file_path):
    if file_path.endswith('.lua'):
        output_file = file_path.replace('.lua', '.decomp.lua')
    elif file_path.endswith('.lp'):
        output_file = file_path.replace('.lp', '.decomp.lp')
    else:
        print(f"Unsupported file format: {file_path}")
        return

    print(f"Decompiling {file_path} to {output_file}")

    try:
        with open(output_file, 'w') as output:
            subprocess.run(['java', '-jar', unluac_path, file_path], stdout=output, check=True)
        print(f"Successfully decompiled {file_path} to {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error decompiling {file_path}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def decompile_directory(unluac_path, directory):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.lua') or file.endswith('.lp'):
                file_path = os.path.join(root, file)
                decompile_file(unluac_path, file_path)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python decompile_lua.py <path_to_unluac.jar> <directory>")
        sys.exit(1)

    unluac_path = sys.argv[1]
    directory = sys.argv[2]

    if not os.path.isfile(unluac_path):
        print(f"Error: {unluac_path} does not exist.")
        sys.exit(1)

    if not os.path.isdir(directory):
        print(f"Error: {directory} does not exist.")
        sys.exit(1)

    decompile_directory(unluac_path, directory)
