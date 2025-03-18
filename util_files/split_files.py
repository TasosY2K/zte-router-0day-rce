import os

def from_hex(hex_string):
    return bytes.fromhex(hex_string).decode('latin1')

def sanitize_path(file_path):
    safe_path = os.path.normpath(file_path)
    
    safe_path = safe_path.lstrip(os.sep)

    if safe_path.startswith(".."):
        safe_path = safe_path.replace("..", "")

    return safe_path

def split_files(joined_file_path, output_folder):
    with open(joined_file_path, "r") as joined_file:
        content = joined_file.read()

    file_sections = content.split("###FILE_START###")

    for section in file_sections:
        if not section.strip():
            continue

        try:
            file_path_line, file_content = section.split("###CONTENT_START###")
            file_path = file_path_line.strip().replace("FILE_PATH: ", "").strip()

            sanitized_file_path = sanitize_path(file_path)

            output_path = os.path.join(output_folder, sanitized_file_path)

            hex_content = file_content.split("###CONTENT_END###")[0].strip()

            decoded_content = from_hex(hex_content)

            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            with open(output_path, "wb") as output_file:
                output_file.write(decoded_content.encode('latin1'))

            print(f"Extracted: {output_path}")

        except ValueError:
            print("Error processing section, skipping...")

joined_file = "out"
output_folder = "output_split_folder"

split_files(joined_file, output_folder)
