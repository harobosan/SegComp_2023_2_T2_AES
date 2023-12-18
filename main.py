from modules.AESCypher import AESCypher

if __name__ == "__main__":
	aes = AESCypher()
	key = 'ABCDEFGHIJKLMNOP'
	nonce = aes.nonce()
	print(f'KEY  : {key}')
	print(f'NONCE: {nonce}')
	aes.file('text.txt','text_encoded_ecb.txt',key,nonce,10)
	aes.file('text_encoded_ecb.txt','text_decoded_ecb.txt',key,nonce,10,dec=True)
	aes.file('text.txt','text_encoded_ctr.txt',key,nonce,10,opmode='CTR')
	aes.file('text_encoded_ctr.txt','text_decoded_ctr.txt',key,nonce,10,opmode='CTR',dec=True)
	aes.image('image.png','image_encoded_ecb.png',key,nonce,10)
	aes.image('image_encoded_ecb.png','image_decoded_ecb.png',key,nonce,10,dec=True)
	aes.image('image.png','image_encoded_ctr_1.png',key,nonce,1,opmode='CTR')
	aes.image('image_encoded_ctr_1.png','image_decoded_ctr_1.png',key,nonce,1,opmode='CTR',dec=True)
	aes.image('image.png','image_encoded_ctr_5.png',key,nonce,5,opmode='CTR')
	aes.image('image_encoded_ctr_5.png','image_decoded_ctr_5.png',key,nonce,5,opmode='CTR',dec=True)
	aes.image('image.png','image_encoded_ctr_9.png',key,nonce,9,opmode='CTR')
	aes.image('image_encoded_ctr_9.png','image_decoded_ctr_9.png',key,nonce,9,opmode='CTR',dec=True)
	aes.image('image.png','image_encoded_ctr_13.png',key,nonce,13,opmode='CTR')
	aes.image('image_encoded_ctr_13.png','image_decoded_ctr_13.png',key,nonce,13,opmode='CTR',dec=True)