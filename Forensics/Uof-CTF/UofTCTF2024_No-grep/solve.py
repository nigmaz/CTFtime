x="34 95 17 57 2 16 3 18 68 16 12 54 4 82 24 45 35 0 40 63 20 10 58 25 3 65 0 20".split(' ')
y="87 48 119 77 97 100 101 105 116 116 104 105 115 102 97 114".split(' ')

flag=""
c=0
for n in range(len(x)):
    if c > len(y)-1:
        c=0
    flag+=chr(int(x[n])^int(y[c]))
    c+=1
print(flag)