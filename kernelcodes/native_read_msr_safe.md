[TOC]
# native_read_msr_safe
通过添加异常表安全的调用rdmsr，防止GP异常造成系统crash
```c
static inline unsigned long long native_read_msr_safe(unsigned int msr,
						      int *err)
{
	DECLARE_ARGS(val, low, high);

	asm volatile("2: rdmsr ; xor %[err],%[err]\n"
		     "1:\n\t"
		     ".section .fixup,\"ax\"\n\t"
		     "3:  mov %[fault],%[err] ; jmp 1b\n\t"
		     ".previous\n\t"
		     _ASM_EXTABLE(2b, 3b)
		     : [err] "=r" (*err), EAX_EDX_RET(val, low, high)
		     : "c" (msr), [fault] "i" (-EIO));
	return EAX_EDX_VAL(val, low, high);
}
```
其中
```asm
#define EAX_EDX_RET(val, low, high)	"=a" (low), "=d" (high)
```
+ 当rdmsr出现异常时跳转到"3:  mov %[fault],%[err]"执行
+ 输出 err使用动态分配寄存器；low使用eax寄存器；high使用edx寄存器
+ 输入 msr使用ecx寄存器，输入fault使用立即数0xfffffffb

## .section .fixup, "ax"
在elf中.section用法为 http://web.mit.edu/rhel-doc/3/rhel-as-en-3/section.html
```
.section name [, "flags"[, @type[, @entsize]]]
```
如
```asm
.section .fixup, "ax"
...
.prvious
```
作用将.section和.previous之间的代码添加到.fixup section，代码的flag为"ax"，flag说明
+ a 可重定位段
+ w 可写段
+ x 可执行段

## _ASM_EXTABLE
其中_ASM_EXTABLE定义为
```asm
#ifdef __ASSEMBLY__
# define _ASM_EXTABLE(from,to)                  \
    .pushsection "__ex_table","a" ;             \
    .balign 8 ;                     \
    .long (from) - . ;                  \
    .long (to) - . ;                    \
    .popsection
```
+ .pushsection和.section的功能相似，将代码添加到__ex_table section，作用配置异常表，如果出现异常时rip值为from，则修改rip为to，跳转到to进行处理。将from和to填充到**exception_table_entry**结构体
```
crash> struct exception_table_entry
struct exception_table_entry {
    int insn;
    int fixup;
}
SIZE: 8
```
+ 在64位系统下通过".long (from) - ."的方式在不改变exception_table_entry结构体大小的情况下保存insn和fixup，从exception_table_entry计算from和to的实际值
```c
static inline unsigned long
ex_insn_addr(const struct exception_table_entry *x)
{
	return (unsigned long)&x->insn + x->insn;
}
static inline unsigned long
ex_fixup_addr(const struct exception_table_entry *x)
{
	return (unsigned long)&x->fixup + x->fixup;
}
```

# 异常表分析

## __ex_table
查看vmlinux中的__ex_table section信息
```
[root@centos7 ~]# objdump -hj __ex_table /usr/lib/debug/lib/modules/3.10.0-957.5.1.el7.x86_64/vmlinux

/usr/lib/debug/lib/modules/3.10.0-957.5.1.el7.x86_64/vmlinux:     file format elf64-x86-64

Sections:
Idx Name          Size      VMA               LMA               File off  Algn
  2 __ex_table    00002050  ffffffff8177c3e0  000000000177c3e0  0097c3e0  2**3
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, DATA
```
查看vmlinux中的__ex_table section的内容
```
[root@centos7 ~]# objdump -sj __ex_table /usr/lib/debug/lib/modules/3.10.0-957.5.1.el7.x86_64/vmlinux | head -n 6

/usr/lib/debug/lib/modules/3.10.0-957.5.1.el7.x86_64/vmlinux:     file format elf64-x86-64

Contents of section __ex_table:
 ffffffff8177c3e0 16cc89ff 1cdcffff a5d589ff 1edcffff  ................
 ffffffff8177c3f0 94de89ff 20dcffff 5afb89ff 2cdcffff  .... ...Z...,...
```
+ __ex_table中保存的是**exception_table_entry**结构体信息，第一个insn和fixup为0xff89cc16和0xffffdc1c

## __start___ex_table和__stop___ex_table
linux使用__start___ex_table和__stop___ex_table两个全局变量保存__ex_table的起始和终止地址，在**search_exception_tables**函数中会使用
```c
/* Given an address, look for it in the exception tables. */
const struct exception_table_entry *search_exception_tables(unsigned long addr)
{
	const struct exception_table_entry *e;

	e = search_extable(__start___ex_table, __stop___ex_table-1, addr);
	if (!e)
		e = search_module_extables(addr);
	return e;
}
```
从System.map中可查看到__start___ex_table和__stop___ex_table的符号表
```
[root@centos7 ~]# grep -E '__start___ex_table|__stop___ex_table' /boot/System.map-3.10.0-957.5.1.el7.x86_64
ffffffff8177c3e0 R __start___ex_table
ffffffff8177e430 R __stop___ex_table
```

## exception_table_entry
使用gdb查看第一个exception_table_entry结构体内容
```
[root@centos7 ~]# gdb -q /usr/lib/debug/lib/modules/3.10.0-957.5.1.el7.x86_64/vmlinux
Reading symbols from /usr/lib/debug/usr/lib/modules/3.10.0-957.5.1.el7.x86_64/vmlinux...done.
(gdb) set $e=(struct exception_table_entry *)0xffffffff8177c3e0
(gdb) p /x *$e
$1 = {insn = 0xff89cc16, fixup = 0xffffdc1c}
```
根据**ex_insn_addr**和**ex_fixup_addr**函数计算from和to
```
(gdb) set $from=((unsigned long)&$e->insn + $e->insn)
(gdb) p /x $from
$2 = 0xffffffff81018ff6
(gdb) set $to=((unsigned long)&$e->fixup + $e->fixup)
(gdb) p /x $to
$3 = 0xffffffff8177a000
```
查看from对应的指令，正好就是native_read_msr_safe中的rdmsr指令
```
(gdb) disassemble 0xffffffff81018ff6,+2
Dump of assembler code from 0xffffffff81018ff6 to 0xffffffff81018ff8:
   0xffffffff81018ff6 <native_read_msr_safe+6>: rdmsr
(gdb) disassemble native_read_msr_safe
Dump of assembler code for function native_read_msr_safe:
   0xffffffff81018ff0 <+0>:     push   %rbp
   0xffffffff81018ff1 <+1>:     mov    %edi,%ecx
   0xffffffff81018ff3 <+3>:     mov    %rsp,%rbp
   0xffffffff81018ff6 <+6>:     rdmsr
   0xffffffff81018ff8 <+8>:     xor    %ecx,%ecx
   0xffffffff81018ffa <+10>:    mov    %eax,%eax
   0xffffffff81018ffc <+12>:    shl    $0x20,%rdx
   0xffffffff81019000 <+16>:    mov    %ecx,(%rsi)
   0xffffffff81019002 <+18>:    or     %rax,%rdx
   0xffffffff81019005 <+21>:    mov    %rdx,%rax
   0xffffffff81019008 <+24>:    pop    %rbp
   0xffffffff81019009 <+25>:    retq
End of assembler dump.
```
查看to对应的指令，对应native_read_msr_safe中的fixup中的内容
```
(gdb) disassemble $to,+10
Dump of assembler code from 0xffffffff8177a000 to 0xffffffff8177a00a:
   0xffffffff8177a000 <__irqentry_text_end+2132>:       mov    $0xfffffffb,%ecx
   0xffffffff8177a005 <__irqentry_text_end+2137>:       jmpq   0xffffffff81018ffa <native_read_msr_safe+10>
End of assembler dump.
```

## do_general_protection
linux通过**set_intr_gate**函数设置了X86_TRAP_GP异常的处理函数
```c
set_intr_gate(X86_TRAP_GP, general_protection);
```
实际调用do_general_protection函数
```
ENTRY(general_protection)
        RING0_EC_FRAME
        pushl_cfi $do_general_protection
        jmp error_code
        CFI_ENDPROC
END(general_protection)
```
在do_general_protection中判断出现GP异常是否是内核态
```c
	if (!user_mode(regs)) {
		if (fixup_exception(regs))
			goto exit;

		tsk->thread.error_code = error_code;
		tsk->thread.trap_nr = X86_TRAP_GP;
		if (notify_die(DIE_GPF, "general protection fault", regs, error_code,
			       X86_TRAP_GP, SIGSEGV) != NOTIFY_STOP)
			die("general protection fault", regs, error_code);
		goto exit;
	}
```
+ 如果是内核态调用**fixup_exception**函数进行处理
+ 如果fixup_exception未查找到对应的fixup，则系统会crash

## fixup_exception
在fixup_exception中调用**search_exception_tables**根据regs->ip查看对应的fixup，如果查找到fixup则将regs->ip更新为fixup
```c
	fixup = search_exception_tables(regs->ip);
	if (fixup) {
		new_ip = ex_fixup_addr(fixup);

		if (fixup->fixup - fixup->insn >= 0x7ffffff0 - 4) {
			/* Special hack for uaccess_err */
			current_thread_info()->uaccess_err = 1;
			new_ip -= 0x7ffffff0;
		}
		regs->ip = new_ip;
		return 1;
	}
```

参考 
[内核入门] gcc中内嵌汇编 http://bbs.chinaunix.net/thread-4104717-1-1.html
https://www.mjmwired.net/kernel/Documentation/x86/exception-tables.txt
