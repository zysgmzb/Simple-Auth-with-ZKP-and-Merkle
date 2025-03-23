import merkle_tree
import untils
import zokrates_cmd
import onchain_verify

test_tree = merkle_tree.MerkleTree()
user1, user1_pass = "admin123456", "admin"
user2, user2_pass = "zysgmzb654321", "123456"
user1_leaf = merkle_tree.hashlib.sha256(user1.encode()).hexdigest()
user2_leaf = merkle_tree.hashlib.sha256(user2.encode()).hexdigest()
test_tree.update_leaf(0, user1_leaf)
test_tree.update_leaf(1, user2_leaf)
root, leaf, direction, path = test_tree.generate_proof_path_and_direction(1)
# zokrates_cmd.setup("merkle.zok")
# zokrates_cmd.generate_proof(root, leaf, direction, path, 1)

token = untils.generate_user_key_format(1, user2_pass)
print(token)
abc, inputs = untils.decode_user_proof(token, user2_pass)
anvil_process = onchain_verify.start_anvil()
onchain_verify.compile_verifier()
verifier_address = onchain_verify.deploy_zk_verifier()
print(verifier_address)
print(onchain_verify.verify(abc, inputs, verifier_address))
onchain_verify.stop_anvil(anvil_process)
