import subprocess
import json
import os
import untils


def setup(filename):
    try:
        subprocess.run(["zokrates", "compile", "-i", filename], check=True)

        subprocess.run(
            ["zokrates", "setup"], check=True)

        subprocess.run(
            ["zokrates", "export-verifier"], check=True)

    except subprocess.CalledProcessError as e:
        print(f"Error setup: {e}")
        return None


def generate_proof(root, leaf, direction, path, userid):
    outfilename = f"userid_{userid}_proof.json"
    try:
        inputs = []
        inputs += untils.convert_u256_to_u32_list(int(root, 16))
        inputs += untils.convert_u256_to_u32_list(int(leaf, 16))
        inputs += direction
        for i in range(7):
            inputs += untils.convert_u256_to_u32_list(int(path[i], 16))
        args = ["zokrates", "compute-witness", "-a"] + [str(i) for i in inputs]
        subprocess.run(args, check=True)

        subprocess.run(["zokrates", "generate-proof",
                       "-j", outfilename], check=True)

        with open(outfilename, "r") as f:
            proof = json.load(f)
        return proof
    except subprocess.CalledProcessError as e:
        print(f"Error generating proof: {e}")
        return None


def clear_user_proof(userid):
    delete_file = ["out.wtns", "witness", f"userid_{userid}_proof.json"]
    for filename in delete_file:
        if os.path.exists(filename):
            os.remove(filename)
