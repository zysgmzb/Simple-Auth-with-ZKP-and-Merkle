import hashlib


class MerkleTree:
    def __init__(self):
        self.tree = ["0"*64]*(2**8-1)
        self.update_tree()

    def update_tree(self):
        for i in range(127):
            place = 126-i
            self.tree[place] = hashlib.sha256(bytes.fromhex(
                self.tree[place*2+1] + self.tree[place*2+2])).hexdigest()

    def check_leaf(self, leaf):
        leaf = leaf.lower()
        if type(leaf) != str or len(leaf) != 64 or not all(c in '0123456789abcdef' for c in leaf):
            return False
        return True

    def update_leaf(self, index, leaf):
        if index < 0 or index > 127:
            return False
        if self.check_leaf(leaf):
            self.tree[index+127] = leaf
            self.update_tree()
            return True

    def generate_proof_path_and_direction(self, index):
        if index < 0 or index > 127:
            return False
        leaf = self.tree[index+127]
        direction = [int(i) for i in list(bin(index)[2:].zfill(7))][::-1]
        path = [""]*7
        for i in range(7):
            neighbor_place = index - 1 if direction[i] == 1 else index + 1
            path[i] = self.tree[neighbor_place + 2**(7-i) - 1]
            index //= 2
        return self.tree[0], leaf, direction, path
