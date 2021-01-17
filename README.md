# ctf.0xl4ugh_leaky_pipe

### Solution
We were given a binary.
```
file leaky_pipe
leaky_pipe: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=87689ef50fdd96e017be4819a94fe97f3bac65ce, for GNU/Linux 3.2.0, not stripped
```
We first run it to see what it does
```
We have just fixed the plumbing systm, let's hope there's no leaks!
>.> aaaaah shiiit wtf is dat address doin here...  0x7fffb50a6c80
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
zsh: segmentation fault  ./leaky_pipe
```
It seems like a buffer overflow because there is a segmentation fault. Moreover there is also a interesting memory address. Let's look it into ghidra.
```
undefined8 main(void)

{
  basic_ostream *pbVar1;
  basic_ostream<char,std::char_traits<char>> *this;
  ssize_t sVar2;
  undefined8 uVar3;
  undefined local_28 [32];
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  pbVar1 = std::operator<<((basic_ostream *)std::cout,
                           "We have just fixed the plumbing systm, let\'s hope there\'s no leaks!");
  std::basic_ostream<char,std::char_traits<char>>::operator<<
            ((basic_ostream<char,std::char_traits<char>> *)pbVar1,
             std::endl<char,std::char_traits<char>>);
  pbVar1 = std::operator<<((basic_ostream *)std::cout,
                           ">.> aaaaah shiiit wtf is dat address doin here...  ");
  this = (basic_ostream<char,std::char_traits<char>> *)
         std::basic_ostream<char,std::char_traits<char>>::operator<<
                   ((basic_ostream<char,std::char_traits<char>> *)pbVar1,local_28);
  std::basic_ostream<char,std::char_traits<char>>::operator<<
            (this,std::endl<char,std::char_traits<char>>);
  sVar2 = read(0,local_28,0x40);
  if (sVar2 < 5) {
    pbVar1 = std::operator<<((basic_ostream *)std::cout,"no smol input plz");
    std::basic_ostream<char,std::char_traits<char>>::operator<<
              ((basic_ostream<char,std::char_traits<char>> *)pbVar1,
               std::endl<char,std::char_traits<char>>);
    uVar3 = 0xffffffff;
  }
  else {
    uVar3 = 0;
  }
  return uVar3;
}
```
This is the main funtion 
We can see that there is an array of 32 elements <code> local_28 [32] </code> that can take an input of some data <code> read(0,local_28,0x40); </code> <br>
Now it's time to use this array to overflow and overwrite the rbp register.
Let's look it into GDB.
```
We have just fixed the plumbing systm, let's hope there's no leaks!
>.> aaaaah shiiit wtf is dat address doin here...  0x7fffffffe010
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000555555555295 in main ()
(gdb) info registers
rax            0x0                 0
rbx            0x0                 0
rcx            0x7ffff7bb3e2e      140737349631534
rdx            0x40                64
rsi            0x7fffffffe010      140737488347152
rdi            0x0                 0
rbp            0x4141414141414141  0x4141414141414141
rsp            0x7fffffffe038      0x7fffffffe038
r8             0x0                 0
r9             0x7fffffffde00      140737488346624
r10            0xfffffffffffff286  -3450
r11            0x246               582
r12            0x5555555550a0      93824992235680
r13            0x0                 0
r14            0x0                 0
r15            0x0                 0
rip            0x555555555295      0x555555555295 <main+252>
eflags         0x10246             [ PF ZF IF RF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
```
We see that the RBP register is overwritten with the hex value 41 that means "A" as we given in input and the RIP register now points at <code>0x555555555295</code> with offset <code> <main+252> </code> <br>
Now we have analyzed the binary. Let's go to write the exploit.
First we need to calculate the offset that is 32 bytes + 8 bytes to overflow the RBP register.
