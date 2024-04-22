def main():
	file_path = "flag.txt.EXTEN"
	with open(file_path, "rb") as file:
		data = file.read()

		cipher = data[0:0x28]
		key = data[0x28:]

		result = b""
		for i in range(0, 0x28):
			result += bytes([cipher[i] ^ 0xDD ^ key[i]])
		print(result)

if __name__ == "__main__":
	main()