
+ 编译删除SYMBOL TABLE
go build -ldflags="-s -w" hello.go
+ 禁止优化
go build -gcflags="-N -l" hello.go

参考
The Go low-level calling convention on x86-64
https://dr-knz.net/go-calling-convention-x86-64.html
BPF和Go：在Linux中内省的现代方式[译]
https://tonybai.com/2020/12/25/bpf-and-go-modern-forms-of-introspection-in-linux/
BPF and Go: Modern forms of introspection in Linux
https://medium.com/bumble-tech/bpf-and-go-modern-forms-of-introspection-in-linux-6b9802682223
How to use a struct for golang fuction args in bpftrace
https://stackoverflow.com/questions/65413266/how-to-use-a-struct-for-golang-fuction-args-in-bpftrace
