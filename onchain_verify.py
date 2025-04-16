import subprocess
from eth_account import Account
from web3 import Web3
import json

Account.enable_unaudited_hdwallet_features()


def start_anvil():
    command = [
        'anvil',
        '--disable-console-log',
        '--silent'
    ]

    try:
        with open('/dev/null', 'w') as devnull:
            process = subprocess.Popen(command, stdout=devnull, stderr=devnull)

        return process
    except Exception as e:
        print(f"Failed to start Anvil: {e}")


def stop_anvil(process):
    try:
        process.terminate()
        process.wait()
    except Exception as e:
        print(f"Failed to stop Anvil: {e}")


def compile_verifier():
    cmd = "solc verifier.sol --optimize --bin --abi --overwrite --output-dir ./contracts/"
    try:
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to compile verifier: {e}")
        return False
    return True


def deploy_zk_verifier():
    deployer_private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    web3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))

    contract_abi = json.load(open('./contracts/Verifier.abi'))

    contract_bytecode = open('./contracts/Verifier.bin').read()

    deploy_address = web3.eth.account.from_key(deployer_private_key).address

    Contract = web3.eth.contract(bytecode=contract_bytecode, abi=contract_abi)

    construct_txn = Contract.constructor().build_transaction({
        'from': deploy_address,
        'nonce': web3.eth.get_transaction_count(deploy_address),
        'gas': 2000000,
        'gasPrice': web3.to_wei('21', 'gwei'),
    })

    signed_txn = web3.eth.account.sign_transaction(
        construct_txn, private_key=deployer_private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)

    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    out_address = tx_receipt.contractAddress
    return out_address


def verify(abc, inputs, verifier_address):
    web3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))

    contract_abi = json.load(open('./contracts/Verifier.abi'))

    Contract = web3.eth.contract(verifier_address, abi=contract_abi)

    verify_result = Contract.functions.verifyTx(abc, inputs).call()
    # print(verify_result)
    return verify_result
