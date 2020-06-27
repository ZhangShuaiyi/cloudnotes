[toc]

# MSR介绍

## 什么是MSR
Model Specific Register (MSR)是一组特殊的寄存器，通过这些寄存器可以获取CPU信息或配置CPU相关的功能，如获取CPU温度、配置APIC等。

## 如何读写MSR
通过RDMSR/WRMSR指令读写MSR，每个msr有一个相应的ID，即msr index
+ rdmsr 读取指定msr的内容，要读取的index存放在ECX中，读取到的结果保持在EDX:EAX
+ wrmsr 将EDX:EAX的内容写入指定的msr中，要写入的msr index存放在ECX中

**注意**
+ 要使用rdmsr和wrmsr命令需要先使用cpuid确认CPUID.01h:EDX[bit 5]是否为1
```
   feature information (1/edx):
      x87 FPU on chip                        = true
      virtual-8086 mode enhancement          = true
      debugging extensions                   = true
      page size extensions                   = true
      time stamp counter                     = true
      RDMSR and WRMSR support                = true
      physical address extensions            = true
```
+ rdmsr和wrmsr需要运行在privilege level 0下，否则会产生general protection exception异常
+ rdmsr和wrmsr指令有可能产生general protection exception（即#GP）异常。

## 命令行工具
msr-tools提供了rdmsr和wrmsr这两个命令可以用来在用户态读写msr，内核的msr模块会创建/dev/cpu/{CPU NUM}/msr文件，rdmsr和wrmsr命令通过该文件读取/设置指定CPU的msr。

### 获取CPU当前温度
通过MSR_TEMPERATURE_TARGET(1A2H)和IA32_THERM_STATUS(19CH)可以计算CPU的当前温度
+ MSR_TEMPERATURE_TARGET(1A2H)的23:16位为CPU的阈值温度
+ IA32_THERM_STATUS(19CH) 的22:16位为当前距离阈值温度的值
```
[root@shyi ~]# # cpu0的阈值温度为90度
[root@shyi ~]# rdmsr -p0 --bitfield 23:16 -u 0x1a2
90
[root@shyi ~]# # cpu0距离阈值温度的值为73
[root@shyi ~]# rdmsr -p0 --bitfield 22:16 -u 0x19c
73
```
可以计算出cpu0的当前温度为90 - 73 = 17度

### 查看APIC Base地址
通过IA32_APIC_BASE(1BH)这个msr可以查看/配置APIC信息
+ bit[10] Enable x2APIC mode
+ bit[11] APIC Global Enable (R/W)
+ bit[12:35] APIC Base (R/W)
```
[root@shyi ~]# rdmsr -p0 --bitfield 10:10 0x1b
1
[root@shyi ~]# rdmsr -p0 --bitfield 11:11 0x1b
1
[root@shyi ~]# rdmsr -p0 --bitfield 35:12 0x1b
fee00
```
处于x2APIC模式，APIC Base地址为0xfee00000

# rdmsr指令

## 运行rdmsr指令
通过rdmsr指令可以读取msr内容，但rdmsr指令需要在privilege level 0下，在用户态运行rdmsr指令会产生general protection exception异常
编写用户态测试程序
```c
#include <stdio.h>

int main(int argc, char *argv[]) {
    unsigned int low, high;
    unsigned int index;

    index = 0x1b;
    // 输入 ECX = index
    // 输出 EAX = low, EDX = high
    asm volatile("rdmsr"
            : "=a"(low), "=d"(high)
            : "c"(index));
    printf("output:0x%x:%x\n", high, low);
}
```
程序运行崩溃，报"Segmentation fault"，在内核日志查看到如下信息
```
traps: test_rdmsr[14619] general protection ip:400538 sp:7fffa1e304e0 error:0 in test_rdmsr[400000+1000]
```

编写测试module
```c
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");

void test_rdmsr(void)
{
    unsigned int low, high;
    unsigned int index;

    index = 0x1b;
    // 输入 ECX = index
    // 输出 EAX = low, EDX = high
    asm volatile("rdmsr"
            : "=a"(low), "=d"(high)
            : "c"(index));
    pr_info("testmsr high:0x%x low:%x\n", high, low);
}

static int hello_init(void)
{
    pr_info("Module init: Hello linux kernel.\n");
    test_rdmsr();
    return (0);
}

static void hello_exit(void)
{
    pr_info("Module exit: Bye-bye linux kernel.\n");
}

module_init(hello_init);
module_exit(hello_exit);
```
Makefile文件
```
obj-m += testmsr.o
PWD := $(shell pwd)
KDIR := /usr/src/kernels/$(shell uname -r)/
all:
        make -C $(KDIR) M=$(PWD) modules
clean:
        rm -f *.o *.ko *.mod.c
```
make后使用insmod加载模块，dmesg有如下输出
```
testmsr high:0x0 low:fee00d00
```
和使用rdmsr读到的内容相同
```
[root@shyi ~]# rdmsr 0x1b
fee00d00
```

## rdmsr_safe_on_cpu函数
读取未实现的msr会产生general protection exception异常，如果在内核中直接使用rdmsr读取未实现的msr则系统会崩溃
```c
void test_rdmsr(void)
{
    unsigned int low, high;
    unsigned int index;

    index = 0xff;
    // 输入 ECX = index
    // 输出 EAX = low, EDX = high
    asm volatile("rdmsr"
            : "=a"(low), "=d"(high)
            : "c"(index));
    pr_info("testmsr high:0x%x low:%x\n", high, low);
}
```
查看崩溃的dmesg有如下信息
```
general protection fault: 0000 [#1] SMP
```
内核提供了**rdmsr_safe_on_cpu**函数进行安全的rdmsr操作，修改测试module为
```c
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <asm/msr.h>

MODULE_LICENSE("GPL");

void test_rdmsr(unsigned int index)
{
    int err = 0;
    unsigned int low, high;

    err = rdmsr_safe_on_cpu(0, index, &low, &high);

    pr_info("testmsr index:0x%x err:%d high:0x%x low:%x\n",
        index, err, high, low);
}

static int hello_init(void)
{
    pr_info("Module init: Hello linux kernel.\n");
    test_rdmsr(0x1b);
    test_rdmsr(0xff);
    return (0);
}

static void hello_exit(void)
{
    pr_info("Module exit: Bye-bye linux kernel.\n");
}

module_init(hello_init);
module_exit(hello_exit);
```
make后加载驱动，dmesg输出为
```
testmsr index:0x1b err:0 high:0x0 low:fee00d00
testmsr index:0xff err:-5 high:0x813aa840 low:0
```
对于未实现的msr，rdmsr_safe_on_cpu函数返回err非0

# MSR虚拟化

## VMCS配置
在**alloc_loaded_vmcs**中通过**cpu_has_vmx_msr_bitmap**判断是否使用msr_bitmap，如果使用申请一页内存，并msr_bitmap全部设置为1
```c
	if (cpu_has_vmx_msr_bitmap()) {
		loaded_vmcs->msr_bitmap = (unsigned long *)__get_free_page(GFP_KERNEL);
		if (!loaded_vmcs->msr_bitmap)
			goto out_vmcs;
		memset(loaded_vmcs->msr_bitmap, 0xff, PAGE_SIZE);
	}
```
msr_bitmap为4k大小，分为4个1K的连续区域，分别为
+ Read bitmap for low MSRs 通过bit位标识0H--1FFFH范围的msr在rdmsr时是否vm exit
+ Read bitmap for high MSRs 通过bit位标识C0000000H--C0001FFFH范围的msr在rdmsr时是否vm exit
+ Write bitmap for low MSRs 通过bit位标识0H--1FFFH范围的msr在wrmsr时是否vm exit
+ Write bitmap for high MSRs  通过bit位标识C0000000H--C0001FFFH范围的msr在wrmsr时是否vm exit
在**vmx_create_vcpu**中通过vmx_disable_intercept_for_msr配置了一些msr在读写时不触发vm exit
```c
	msr_bitmap = vmx->vmcs01.msr_bitmap;
	vmx_disable_intercept_for_msr(msr_bitmap, MSR_FS_BASE, MSR_TYPE_RW);
	vmx_disable_intercept_for_msr(msr_bitmap, MSR_GS_BASE, MSR_TYPE_RW);
	vmx_disable_intercept_for_msr(msr_bitmap, MSR_KERNEL_GS_BASE, MSR_TYPE_RW);
	vmx_disable_intercept_for_msr(msr_bitmap, MSR_IA32_SYSENTER_CS, MSR_TYPE_RW);
	vmx_disable_intercept_for_msr(msr_bitmap, MSR_IA32_SYSENTER_ESP, MSR_TYPE_RW);
	vmx_disable_intercept_for_msr(msr_bitmap, MSR_IA32_SYSENTER_EIP, MSR_TYPE_RW);
```
关于FS, GS说明，参考 https://wiki.osdev.org/CPU_Registers_x86-64
>FS.base, GS.base
>MSRs with the addresses 0xC0000100 (for FS) and 0xC0000101 (for GS) contain the base addresses of the FS and GS segment registers. These are commonly used for thread-pointers in user code and CPU-local pointers in kernel code. Safe to contain anything, since use of a segment does not confer additional privileges to user code.
>
>In newer CPUs, these can also be written with WRFSBASE and WRGSBASE instructions at any privilege level.
>
>KernelGSBase
>MSR with the address 0xC0000102. Is basically a buffer that gets exchanged with GS.base after a swapgs instruction. Usually used to seperate kernel and user use of the GS register.

## kvm_msr
在arch/x86/kvm/vmx.c中定义的全局变量**kvm_vmx_exit_handlers**记录了不同vm exit对应的处理函数
```c
/*
 * The exit handlers return 1 if the exit was handled fully and guest execution
 * may resume.  Otherwise they set the kvm_run parameter to indicate what needs
 * to be done to userspace and return 0.
 */
static int (*const kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu) = {
	[EXIT_REASON_EXCEPTION_NMI]           = handle_exception,
	[EXIT_REASON_EXTERNAL_INTERRUPT]      = handle_external_interrupt,
	...,
	[EXIT_REASON_MSR_READ]                = handle_rdmsr,
	[EXIT_REASON_MSR_WRITE]               = handle_wrmsr,
	...,
	[EXIT_REASON_PREEMPTION_TIMER]	      = handle_preemption_timer,
};
```
在handle_rdmsr和handle_wrmsr都会调用trace_kvm_msr，
```c
#define trace_kvm_msr_read(ecx, data)      trace_kvm_msr(0, ecx, data, false)
#define trace_kvm_msr_write(ecx, data)     trace_kvm_msr(1, ecx, data, false)
#define trace_kvm_msr_read_ex(ecx)         trace_kvm_msr(0, ecx, 0, true)
#define trace_kvm_msr_write_ex(ecx, data)  trace_kvm_msr(1, ecx, data, true)
```
通过查看内核的kvm:kvm_msr事件，可以获取到虚拟机读写了哪些msr，使用perf命令记录1s内发生的kvm:kvm_msr事件
```
perf record -e kvm:kvm_msr -p $(pidof qemu-kvm) sleep 1
```
使用perf script进行查看，截取部分输出
```
       CPU 0/KVM 1821753 [015] 4831258.258053: kvm:kvm_msr: msr_write 6e0 = 0x10e8aebe830c9e
       CPU 0/KVM 1821753 [015] 4831258.258056: kvm:kvm_msr: msr_write 6e0 = 0x10e8aebd0b2770
       CPU 0/KVM 1821753 [015] 4831258.258093: kvm:kvm_msr: msr_write 830 = 0x2000000fd
       CPU 2/KVM 1821755 [032] 4831258.258124: kvm:kvm_msr: msr_write 6e0 = 0x10e8aebd0b2832
       CPU 0/KVM 1821753 [015] 4831258.258140: kvm:kvm_msr: msr_write 6e0 = 0x10e8aebcf03f42
       CPU 0/KVM 1821753 [015] 4831258.258148: kvm:kvm_msr: msr_read 3b = 0x0
       CPU 2/KVM 1821755 [032] 4831258.258152: kvm:kvm_msr: msr_write 6e0 = 0x10e8aed7f0858e
       CPU 0/KVM 1821753 [015] 4831258.258218: kvm:kvm_msr: msr_write 6e0 = 0x10e8aebe82e1c8
```
+ 6e0H这个msr为IA32_TSC_DEADLINE，写该msr作用是为TSC Deadline Mode模式下的Local APIC设置到期值，在Guest中使用rdmsr可查看该msr
    ```
    [root@shyi ~]# rdmsr -p0 0x6e0
    10e8f8237e8ca8
    ```
+ 830H为IA32_X2APIC_ICR，写该msr可发送IPI
收到在Guest调用rdmsr可在Host中看到对应kvm_msr事件，如在Guest中指定cpu运行rdmsr命令读取msr.
```
[root@shyi ~]# for i in {0..3};do rdmsr -p $i 0x1b;done
fee00d00
fee00c00
fee00c00
fee00c00
```
在Host中先使用"perf record -e kvm:kvm_msr -p $PID"，在执行perf script查看结果
```
[root@host perfs]# perf script | grep msr_read | grep 1b
       CPU 0/KVM 1821753 [021] 4841560.169621: kvm:kvm_msr: msr_read 1b = 0xfee00d00
       CPU 1/KVM 1821754 [020] 4841560.170816: kvm:kvm_msr: msr_read 1b = 0xfee00c00
       CPU 2/KVM 1821755 [015] 4841560.171932: kvm:kvm_msr: msr_read 1b = 0xfee00c00
       CPU 3/KVM 1821756 [023] 4841560.173024: kvm:kvm_msr: msr_read 1b = 0xfee00c00
```

## handle_rdmsr
如果vm因为rdmsr的原因造成vm exit，则kvm会调用handle_rdmsr处理该exit，msr的模拟是由kvm代码实现的。
在**kvm_get_msr_common**中有对未实现的msr的处理，即**ignore_msrs**参数
```c
	default:
		if (kvm_pmu_is_valid_msr(vcpu, msr_info->index))
			return kvm_pmu_get_msr(vcpu, msr_info->index, &msr_info->data);
		if (!ignore_msrs) {
			vcpu_debug_ratelimited(vcpu, "unhandled rdmsr: 0x%x\n",
					       msr_info->index);
			return 1;
		} else {
			vcpu_unimpl(vcpu, "ignored rdmsr: 0x%x\n", msr_info->index);
			msr_info->data = 0;
		}
		break;
```
对于kvm没有实现的msr且ignore_msrs参数为0时，kvm_get_msr_common函数返回1，在handle_rdmsr中处理流程为
```c
	if (vmx_get_msr(vcpu, &msr_info)) {
		trace_kvm_msr_read_ex(ecx);
		kvm_inject_gp(vcpu, 0);
		return 1;
	}
```
如果vmx_get_msr返回值为1，则调用**kvm_inject_gp**函数
```c
static inline void kvm_inject_gp(struct kvm_vcpu *vcpu, u32 error_code)
{
	kvm_queue_exception_e(vcpu, GP_VECTOR, error_code);
}
```
kvm_inject_gp作用向指定vCPU注入general protection异常。
如果设置ignore_msrs参数为1时，Host会打印"ignored rdmsr"，并设置msr的内容为0

最终将msr的内容保存到vCPU的RAX和RDX寄存器
```c
	/* FIXME: handling of bits 32:63 of rax, rdx */
	vcpu->arch.regs[VCPU_REGS_RAX] = msr_info.data & -1u;
	vcpu->arch.regs[VCPU_REGS_RDX] = (msr_info.data >> 32) & -1u;
```
