def int_to_bytes(num):
    # Chuyển số nguyên thành dạng byte và loại bỏ tiền tố '0x'
    hex_string = hex(num)[2:]
    # Đảm bảo chuỗi hex có đủ số lượng ký tự
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string
    # Đảo ngược chuỗi hex và chia thành các cặp ký tự
    hex_bytes = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
    # Đảo ngược thứ tự các cặp ký tự hex
    hex_bytes.reverse()
    # Chuyển đổi các cặp ký tự hex thành các giá trị byte và tạo thành một chuỗi byte
    byte_result = bytes.fromhex(''.join(hex_bytes))
    return byte_result

############### 1
# Số nguyên kết quả từ phép nhân
result_int = 77205325028399246428625144727543316375512475203

# Chuyển đổi số nguyên thành chuỗi byte hex
result_bytes = int_to_bytes(result_int)

print(result_bytes)

############### 2
# Số nguyên kết quả từ phép nhân
result_int = 576728373602368866029583485236697935421371408887

# Chuyển đổi số nguyên thành chuỗi byte hex
result_bytes = int_to_bytes(result_int)

print(result_bytes)

############### 3
# Số nguyên kết quả từ phép nhân
result_int = 443550489437008394034948849149808613388615954563

# Chuyển đổi số nguyên thành chuỗi byte hex
result_bytes = int_to_bytes(result_int)

print(result_bytes)