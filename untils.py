import json
import zlib
import gzip
import zkproof_crypto
import base64


def convert_u256_to_u32_list(input):
    out = [0]*8
    for i in range(8):
        out[7-i] = input >> (i*32) & 0xFFFFFFFF
    return out


def convert_u32_list_to_u256(input):
    out = 0
    for i in range(8):
        out += input[7-i] << (i*32)
    return out


def parse_proof_json(userid):
    filename = f"userid_{userid}_proof.json"
    try:
        with open(filename, "r") as f:
            content = json.load(f)
    except FileNotFoundError:
        print(f"File {filename} not found")
        return None
    proof = content["proof"]
    inputs = content["inputs"]
    a, b, c = proof["a"], proof["b"], proof["c"]
    abc = [a, b, c]
    return abc, inputs


def generate_user_key_raw(userid, password):
    [a, b, c], inputs = parse_proof_json(userid)
    content_a = a[0][2:] + a[1][2:]
    content_b = b[0][0][2:] + b[0][1][2:] + b[1][0][2:] + b[1][1][2:]
    content_c = c[0][2:] + c[1][2:]
    content_inputs = inputs[0][2:] + inputs[1][2:] + inputs[2][2:] + \
        inputs[3][2:] + inputs[4][2:] + \
        inputs[5][2:] + inputs[6][2:] + inputs[7][2:]
    content = bytes.fromhex(content_a + content_b + content_c + content_inputs)
    crc_check = int.to_bytes(zlib.crc32(content), 4, 'big')
    content_all = gzip.compress(content + crc_check)
    content_final = zkproof_crypto.encrypt(password, content_all)
    return content_final


def generate_user_key_format(userid, password):
    proof_encrypted = generate_user_key_raw(userid, password)
    result = "-----BEGIN PROOF-----\n" + \
        base64.encodebytes(proof_encrypted).strip().decode() + \
        "\n-----END PROOF-----"
    return result


def check_format(proof_content):
    if proof_content.startswith("-----BEGIN PROOF-----") and proof_content.endswith("-----END PROOF-----"):
        return True
    else:
        return False


def decode_user_proof(proof_content, password):
    if not check_format(proof_content):
        return "Invalid format"
    proof_content = proof_content.replace("\n", "")[21:-19]
    proof_encrypted = base64.b64decode(proof_content)
    proof_decrypted = zkproof_crypto.decrypt(password, proof_encrypted)
    proof = gzip.decompress(proof_decrypted)
    crcchecker = proof[-4:]
    if crcchecker == zlib.crc32(proof[:-4]).to_bytes(4, 'big'):
        return parse_proof_raw(proof[:-4])
    else:
        return "decrypt failed"


def parse_proof_raw(proof_raw):
    if (len(proof_raw) != 32*16):
        return "Invalid proof"
    a = (int.from_bytes(proof_raw[0:32], 'big'),
         int.from_bytes(proof_raw[32:64], 'big'))
    b = ([int.from_bytes(proof_raw[64:96], 'big'), int.from_bytes(
        proof_raw[96:128], 'big')], [int.from_bytes(proof_raw[128:160], 'big'), int.from_bytes(proof_raw[160:192], 'big')])
    c = (int.from_bytes(proof_raw[192:224], 'big'),
         int.from_bytes(proof_raw[224:256], 'big'))
    inputs = [int.from_bytes(proof_raw[256+32*i:288+32*i], 'big')
              for i in range(8)]
    abc = (a, b, c)
    return abc, inputs
