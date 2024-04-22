# unpackme5

> Password Un7Zip: infected

## [0]. Analysis Challenge

- File được cung cấp là file PE32 và đã được pack bằng cách sử dụng packer `ASPack`.

![detectItEasy.png](./images/detectItEasy.png)

- Tổng quan về packer `MPRESS`:

  - `1.` File sẽ thực thi phần tại code đã được thêm vào.
  - `2.` Lưu trạng thái của các thanh ghi hiện tại bằng lệnh `pushad`.
  - `3.` Giải nén phần code thực thi gốc trước khi được nén.
    - Dựa vào thuật toán nén để khôi phục ngoài các câu lệnh cơ bản còn sử dụng các API.
    - GetModuleHandleA
    - GetProcAddress
    - Từ 2 hàm trên lấy được 3 con trỏ hàm của
    ```
    VirtualAlloc   : cấp phát bộ nhớ ảo
    VirtualFree    : giải phóng
    VirtualProtect : thay đổi quyền truy cập (hàm này sử dụng sau để đảm bảo code sau  khi khôi phục sẽ được bảo vệ)
    ```
  - `4.` Khôi phục lại IAT.

    - GetModuleHandleA
    - GetProcAddress
    - Có 1 số hàm API không được gọi trực tiếp mà gọi bằng lệnh ret (đẩy giá trị vào đỉnh ngay xếp xong ret).

  - `5.` Khôi phục trạng thái thanh ghi bằng popad.
  - `6.` Jump tới OEP của file thưc thi ban đầu.

## [1]. Solve Idea

- Quá trình unpack hoàn tất khi chương trình thực thi bình thường và phân tích bằng IDA sẽ có thể đọc được hàm main (Dễ nhận thấy là khi load bằng IDA sẽ có nhiều hàm hơn khi mà phân tích file đã bị packed).

![pack.png](./images/pack.png)

- Sử dụng x32dbg để unpack file, F9 để nhảy tới entry point (EP) - ở đây ta thấy câu lệnh `pushad` là điểm bắt đầu lưu lại giá trị của các thanh ghi trước khi tiến hành unpack đoạn code đã bị pack của chương trình gốc (Đây là một dấu hiệu tốt khi EntryPoint chính là instruction `pushad`).

![ep.png](./images/ep.png)

- F8 đến ngay sau instruction `pushad` và đặt breakpoint lên trên stack `(đặt 1 memory breakpoint on access tại ESP)`, khi truy cập vào địa chỉ bộ nhớ này được thực hiện, chương trình sẽ dừng lại (đây là dựa vào nguyên lý của pushad và popad để đặt bp).

![bp.png](./images/bp.png)

- Sau khi thực thi lệnh jmp chính là đến địa chỉ của original entry point.

![oep.png](./images/oep.png)

- Tiến hành sử dụng plugin Scylla để tìm Import Address Table và dump file từ trên memory đang được debug.

  - IAT Autosearch -> Get Imports
  - Delete Tree Node
  - Dump
  - Fix Dump

- Khi đó file dump từ trên memory là file `unpackme5_dump_SCY` và load vào IDA ta sẽ đọc được hàm `WinMain`.

![unpack.png](./images/unpack.png)


