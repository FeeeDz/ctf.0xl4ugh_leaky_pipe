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
We can see that there is an array of 32 elements <code> local_28 [32] </code> that can take an input of some data <code> read(0,local_28,0x40); </code>
