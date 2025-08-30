import tkinter as tk
from tkinter import messagebox, filedialog
import hashlib
import struct
import random
import threading
from collections import Counter
import zlib

def pid_to_fc(pid: int) -> int:
    if pid == 0: return 0
    pid_bytes = pid.to_bytes(4, byteorder='little', signed=False)
    buffer = pid_bytes + b'JCMR'
    high = (hashlib.md5(buffer).digest()[0] >> 1)
    return (high << 32) | pid

def fc_to_pid(friend_code: str) -> int:
    cleaned_code = friend_code.replace("-", "")
    pid = int(cleaned_code) & 0xFFFFFFFF
    return pid

def format_fc(fc_decimal: int) -> str:
    fc_string = f"{fc_decimal:012d}"
    return f"{fc_string[:4]}-{fc_string[4:8]}-{fc_string[8:]}"

def is_fc_or_pid(user_input: str) -> int:
    # 0 = fc, 1 = pid, 2 = invalid input
    if "-" in user_input and len(user_input) == 14 and (user_input[4] == "-" and (user_input[9] == "-")):
        return 0
    else:
        try:
            user_input = int(user_input)
            return 1 if 0 < user_input < 1_000_000_000 else 2
        except ValueError:
            return 2

def converter() -> None:
    user_input = user_entry.get()
    input_type = is_fc_or_pid(user_input)
    if input_type == 0:
        result = fc_to_pid(user_input)
        result_str = "pid: "
    elif input_type == 1:
        result = format_fc(pid_to_fc(int(user_input)))
        result_str = "fc: "
    else:
        result = "invalid input: " + user_input
        result_str = ""
    result_label.config(text=f"{result_str}{result}")


def show_credits() -> None:
    credits_text = "original program by nervosa and day\nimproved by hyperlexus\nv2.1"
    messagebox.showinfo("credits", credits_text)


def calculate_crc32(raw_bytes: bytes) -> int:
    crc_value = zlib.crc32(raw_bytes) & 0xFFFFFFFF
    return crc_value

def process_file_data(file_path: str) -> None:
    with open(file_path, 'rb') as file:
        file.seek(0x40)
        raw_values = file.read(0x3C)  # read 0x40-0x7B

    little_endian_bytes = bytearray()
    for i in range(0, len(raw_values), 4):
        little_endian_bytes.extend(reversed(raw_values[i:i + 4]))
    crc_value = calculate_crc32(little_endian_bytes)

    with open(file_path, 'r+b') as file:
        file.seek(0x7C)
        crc_bytes = struct.pack('<I', crc_value)[::-1]  # reverse
        file.write(crc_bytes)

def bump_id(file_path: str, offset: int) -> bytes:
    with open(file_path, 'r+b') as f:
        f.seek(offset)
        byte_value_as_bytes = f.read(1)

        original_byte_int = int.from_bytes(byte_value_as_bytes, 'big')

        new_byte_int = original_byte_int + 1
        if new_byte_int > 255:
            raise ValueError(offset)

        f.seek(offset)

        new_byte_bytes = new_byte_int.to_bytes(1, 'big')
        f.write(new_byte_bytes)
        print(f"{hex(original_byte_int)} -> {hex(new_byte_int)} at {hex(offset)}")
    return new_byte_bytes

# write decimal as hex to 0x5C-0x5F in rkp
def write_hex_to_rkp() -> None:
    crc_user_input = entry_crc.get()
    input_type = is_fc_or_pid(crc_user_input)
    if input_type == 0: decimal_value_int = fc_to_pid(crc_user_input)
    elif input_type == 1: decimal_value_int = int(crc_user_input)
    else:
        result_crc_label.config(text="failure! invalid input.")
        return
    # take rkp as input
    file_path = filedialog.askopenfilename(title="select license file", filetypes=[("RKP files", "*.rkp")])
    try:
        hex_value = struct.pack('<I', decimal_value_int)
        hex_value_reversed = hex_value[::-1]

        if file_path:
            with open(file_path, 'r+b') as file:
                file.seek(0x5C)
                file.write(hex_value_reversed)  # writes hex value

            # make fc stick by updating player ids (pseudo and authentic) (ty lex)
            try:
                byte_4c = bump_id(file_path, 0x4C)
                byte_58 = bump_id(file_path, 0x58)
            except ValueError as e:
                result_crc_label.config(text=f"error!\noverflow protection.\nbyte at {hex(e.args[0])} was already FF,\nplease make a new rkp.")
                return
            process_file_data(file_path)  # updates crc

            result_crc_label.config(text=f"success!\nset fc to {format_fc(pid_to_fc(decimal_value_int))}"
                                         f"\n0x4C byte: {byte_4c.hex()}"
                                         f"\n0x58 byte: {byte_58.hex()}")
    except ValueError as ve:
        messagebox.showerror("Input Error", str(ve))
    except Exception as e:
        messagebox.showerror("Error", str(e))

root = tk.Tk()
root.title("change fc")
root.configure(bg='#E6E6FA')

main_frame = tk.Frame(root, bg='#E6E6FA')
main_frame.pack(pady=20, padx=20)

# converter
friend_code_frame = tk.LabelFrame(main_frame, text="converter", bg='#E6E6FA', font=("Helvetica", 14))
friend_code_frame.pack(padx=10, pady=10, fill="both", expand=True)

instruction_label = tk.Label(friend_code_frame, text="enter FC or PID", bg='#E6E6FA', font=("Helvetica", 12))
instruction_label.pack(pady=5)

user_entry = tk.Entry(friend_code_frame, width=20, font=("Helvetica", 12), bg='#FFFFFF', borderwidth=2, relief="groove")
user_entry.pack(pady=5)

calculate_pid_button = tk.Button(friend_code_frame, text="convert", command=converter, font=("Helvetica", 12), bg='#7B68EE', fg='white', relief="raised")
calculate_pid_button.pack(pady=5)

result_label = tk.Label(friend_code_frame, text="", bg='#E6E6FA', font=("Helvetica", 12))
result_label.pack(pady=10)

# write fc
crc_frame = tk.LabelFrame(main_frame, text="write new fc", bg='#E6E6FA', font=("Helvetica", 14))
crc_frame.pack(padx=10, pady=10, fill="both", expand=True)

instruction_label_2 = tk.Label(crc_frame, text="enter FC or PID", bg='#E6E6FA', font=("Helvetica", 12))
instruction_label_2.pack(pady=5)

entry_crc = tk.Entry(crc_frame, width=20, font=("Helvetica", 12), bg='#FFFFFF', borderwidth=2, relief="groove")
entry_crc.pack(pady=5)

write_hex_button = tk.Button(crc_frame, text="write fc to rkp", command=write_hex_to_rkp, font=("Helvetica", 12), bg='#7B68EE', fg='white', relief="raised")
write_hex_button.pack(pady=5)

result_crc_label = tk.Label(crc_frame, text="", bg='#E6E6FA', font=("Helvetica", 12))
result_crc_label.pack(pady=10)

show_credits_button = tk.Button(main_frame, text="Credits", command=show_credits, font=("Helvetica", 12), bg='#7B68EE', fg='white', relief="raised")
show_credits_button.pack(pady=10)


root.mainloop()
