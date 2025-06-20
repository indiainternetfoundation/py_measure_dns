import subprocess

def check_gcc(cc_name: str) -> bool:
    try:
        subprocess.check_call(
            [cc_name, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def exec_gcc(cc_name: str, flags: list, output_file: str, input_file: str) -> bool:
    try:
        cmd = cc_name + " " + " ".join(flags) + f" -o {output_file} {input_file}"
        subprocess.check_call(cmd, shell=True)
        return True
    except subprocess.CalledProcessError as e:
        print("Compilation failed:", e)
        return False