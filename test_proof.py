import merkle_tree
import untils
import zokrates_cmd

test_tree = merkle_tree.MerkleTree()
user1, user1_pass = "admin123456", "admin"
user2, user2_pass = "zysgmzb654321", "123456"
user1_leaf = merkle_tree.hashlib.sha256(user1.encode()).hexdigest()
user2_leaf = merkle_tree.hashlib.sha256(user2.encode()).hexdigest()
test_tree.update_leaf(0, user1_leaf)
test_tree.update_leaf(1, user2_leaf)
root, leaf, direction, path = test_tree.generate_proof_path_and_direction(1)
# zokrates_cmd.setup("merkle.zok")
# print(path)
# print(test_tree.tree)
input = []
input += untils.convert_u256_to_u32_list(int(root, 16))
input += untils.convert_u256_to_u32_list(int(leaf, 16))
input += direction
for i in range(7):
    input += untils.convert_u256_to_u32_list(int(path[i], 16))
zokrates_cmd.generate_proof(input, 1)
# will not fail if proof success
print(untils.generate_user_key_format(1, user2_pass))
