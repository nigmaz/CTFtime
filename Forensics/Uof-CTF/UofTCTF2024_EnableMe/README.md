# UofTCTF2024_EnableMe

> You've received a confidential document! Follow the instructions to unlock it. Note: This is not malware

- Challenge cung cấp file `invoice.docm` - đây là một dạng file malware sử dụng macro windows cực kỳ phổ biến khi hacker nhắm đến victim là dân văn phòng.

- Mở file bằng word (trong word thì settings để bật phần `Developer` trong `Custom Ribbon` lên) sau đó thì chọn `Developer\Visual Basic` để view script vba được nhúng bên trong file `invoice.docm`.

```vb
Sub AutoOpen()
    Dim v6 As Variant, v7 As Variant
    v6 = Array(98, 120, 113, 99, 116, 99, 113, 108, 115, 39, 116, 111, 72, 113, 38, 123, 36, 34, 72, 116, 35, 121, 72, 101, 98, 121, 72, 116, 39, 115, 114, 72, 99, 39, 39, 39, 106)
    v7 = Array(44, 32, 51, 84, 43, 53, 48, 62, 68, 114, 38, 61, 17, 70, 121, 45, 112, 126, 26, 39, 21, 78, 21, 7, 6, 26, 127, 8, 89, 0, 1, 54, 26, 87, 16, 10, 84)

    Dim v8 As Integer: v8 = 23

    Dim v9 As String, v10 As String, v4 As String, i As Integer
    v9 = ""
    For i = 0 To UBound(v6)
        v9 = v9 & Chr(v6(i) Xor Asc(Mid(Chr(v8), (i Mod Len(Chr(v8))) + 1, 1)))
    Next i

    v10 = ""
    For i = 0 To UBound(v7)
        v10 = v10 & Chr(v7(i) Xor Asc(Mid(v9, (i Mod Len(v9)) + 1, 1)))
    Next i

    MsgBox v10
End Sub
```

- File vba được define sử dụng hàm `Sub AutoOpen()` cho phép tệp tự động chạy macro khi mở tài liệu.

- Phân tích nội dung của tập lệnh, dường như có một danh sách các ký tự ASCII chạy qua một số `Chr`, `Xor` và các đối số khác nhau trước khi hiển thị kết quả của `v10` trong MsgBox.

- Việc chạy tập lệnh này sẽ đưa ra một MsgBox có nội dung sau: `YOU HAVE BEEN HACKED! Just kidding :)`, nếu thay đổi giá trị hiển thị trong MsgBox từ v10 thành v9 thì ta nhận được flag `uoftctf{d0cx_f1l35_c4n_run_c0de_t000}`.
