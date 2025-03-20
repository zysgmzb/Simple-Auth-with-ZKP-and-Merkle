import subprocess
import json
import os


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


def generate_proof(inputs, userid):
    outfilename = f"userid_{userid}_proof.json"
    try:
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
