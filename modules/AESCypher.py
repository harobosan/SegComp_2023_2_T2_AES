from PIL import Image
from math import ceil
from random import getrandbits

class AESCypher:
	def __init__(self):
		temp = self.readFile('S-BOX.txt')
		temp = [int(h,16) for h in temp.replace('\n','').split(',')]
		self.sbox = [
			{i:temp[i] for i in range(256)},
			{temp[i]:i for i in range(256)}
		]

	def readFile(self, filename):
		text = None

		try:
			file = open(filename, 'r')
			text = file.read()
			file.close()
		except FileNotFoundError:
			print('\n[ERROR] FILE NOT FOUND IN CURRENT DIRECTORY: '+filename+'\n')

		return text

	def keyExpansion(self, key, rounds):
		temp = [ord(c) for c in key]
		words = [temp[i*4:i*4+4] for i in range(4)]

		rcon = [0, 1]
		for i in range(1, rounds):
			con = 2*rcon[i] if rcon[i] < 128 else 283^(2*rcon[i])
			rcon.append(con)
		for i in range(4,rounds*4+4):
			temp = words[i-1]
			if i%4 == 0:
				rot = temp[1:]+[temp[0]]
				sub = [self.sbox[0][b] for b in rot]
				temp = [sub[0]^rcon[int(i/4)]]+sub[1:]
			words.append([words[i-4][j]^temp[j] for j in range(4)])

		return words

	def addRoundKey(self, state, roundKey):
		return [[state[i][j]^roundKey[i][j] for j in range(4)] for i in range(4)]

	def byteSubstitution(self, state, reverse = False):
		state = [[self.sbox[reverse][b] for b in w] for w in state]

		return state

	def shiftRows(self, state, reverse = False):
		if reverse:
			temp = [[state[(4+j-i)%4][i] for i in range(4)] for j in range(4)]
		else:
			temp = [[state[(i+j)%4][i] for i in range(4)] for j in range(4)]

		return temp

	def mixColumns(self, state, reverse = False):
		temp = [[0]*4 for i in range(4)]
		if not reverse:
			galois = [	[2,3,1,1],
						[1,2,3,1],
						[1,1,2,3],
						[3,1,1,2]]
		else:
			galois = [	[14,11,13,9],
						[9,14,11,13],
						[13,9,14,11],
						[11,13,9,14]]

		for i in range(4):
			for j in range(4):
				for k in range(4):
					n = self.moduloIrreductible(state[i][k], galois[j][k])
					temp[i][j] ^= n

		return temp

	def moduloIrreductible(self, byte, factor):
		if factor == 1:
			temp = byte
		elif factor > 1:
			temp = self.moduloIrreductible(byte, int(factor/2))
			temp = (temp << 1 & 0xFF)^(0x00 if temp < 0x80 else 0x1B)
			if factor%2:
				temp = temp^byte

		return temp

	def ISOPadding(self, plaintext):
		if not len(plaintext)%16:
			return plaintext

		for i in range(16-len(plaintext)%16):
			plaintext.append(128 if not i else 0)

		return plaintext

	def nonce(self):
		return [getrandbits(8) for i in range(8)]

	def encryptBlock(self, block, keys, ctr):
		state = self.addRoundKey(block,keys[:4])

		for i in range(1,ctr+1):
			state = self.byteSubstitution(state)
			state = self.shiftRows(state)
			if i < ctr:
				state = self.mixColumns(state)
			state = self.addRoundKey(state, keys[i*4:i*4+4])

		return state

	def decryptBlock(self, block, keys, ctr):
		state = block

		for i in range(ctr,0,-1):
			state = self.addRoundKey(state, keys[i*4:i*4+4])
			if i < ctr:
				state = self.mixColumns(state, True)
			state = self.shiftRows(state, True)
			state = self.byteSubstitution(state, True)

		state = self.addRoundKey(state,keys[:4])

		return state

	def cypher(self, data, key, nonce = None, rounds = 1, opmode = 'ECB', dec = False):
		output = []
		if opmode == 'ECB':
			stream = data if dec else self.ISOPadding(data)
		elif opmode == 'CTR':
			stream = []
			for i in range(ceil(len(data)/16)):
				temp = nonce.copy()
				temp.extend([b for b in (i).to_bytes(8,'big')])
				stream.extend(temp)
		else:
			return

		keys = self.keyExpansion(key, rounds)

		for i in range(int(len(stream)/16)):
			block = [stream[i*16+j*4:i*16+j*4+4] for j in range(4)]
			if opmode == 'ECB' and dec:
				temp = self.decryptBlock(block, keys, rounds)
			else:
				temp = self.encryptBlock(block, keys, rounds)
			output.extend([b for w in temp for b in w])

		if dec:
			for i in range(len(output)-1,-1,-1):
				if output[i] == 0:
					output.pop()
				elif output[i] == 128:
					output.pop()
					break
				else:
					break

		if opmode == 'ECB':
			return output
		if opmode == 'CTR':
			return [data[i]^output[i] for i in range(len(data))]

	def image(self, src, dst, key, nonce = None, rounds = 1, opmode='ECB', dec = False):
		if opmode == 'CTR' and not nonce:
			print('[ERROR] nonce needed for CTR operation mode')
			return

		img = Image.open(src)
		data = [b for p in list(img.getdata()) for b in p]
		state = self.cypher(data, key, nonce, rounds, opmode, dec)
		img.putdata([tuple(state[i:i+3]) for i in range(0,len(state),3)])
		img.save(dst)

	def file(self, src, dst, key, nonce = None, rounds = 1, opmode='ECB', dec = False):
		with open(src, 'rb') as src_file:
			data = [b for b in src_file.read()]
			state = self.cypher(data,key,nonce,rounds,opmode,dec)
			with open(dst,'wb') as dst_file:
				out = ''.join([chr(b) for b in state])
				dst_file.write(bytes(state))
				dst_file.close()
			src_file.close()
