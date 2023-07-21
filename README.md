## SmartChainer

This is an command-line interactive tool that helps you to create ROP Chains by classifying the available gadgets in a small set of operations:

- AddReg
- MoveReg
- StoreMem
- GetStackPtr
- ReadMem
- SubReg
- LoadConst
- StackPivot
- ZeroReg

If you want to move a value from `ebx` to `eax`, you can just use `MoveReg ebx eax` instead of searching for every gadget possibility for this action (like `mov ebx, eax`, `xchg ebx, eax`, `xchg eax, ebx`, `push eax; pop ebx`, etc).

### Installation

Just clone the repository and use it. There are no third party dependencies.

```
git clone https://github.com/viniciusmarangoni/smartchainer
cd smartchainer/

python3 smartchainer.py --help
```

### How to use - TLDR

**The input gadgets.txt file must be an output from rp++**

Initializing the command line tool:

```
python3 smartchainer.py --bad-chars='\x00\x0a\x0d' /tmp/gadgets.txt
```

Show available gadgets for a given operation:

```
ZeroReg
ZeroReg eax

MoveReg
MoveReg ebx *
MoveReg * eax
MoveReg ebx eax
```

Add a shown gadget to your chain:

```
# After running a "ZeroReg eax", a numbered list of chains will be shown
# Use the command below to add the given chain into your ROP chain

append-chain 0
```

Show the ROP Chain being constructed:

```
show rop-chain
```


### SmarcChainer standalone

You can easily make SmartChainer become a single python script file in two steps:

1. Copy source code of `smartchainer.py` file into a new file named `smartchainer-standalone.py` and delete the line `from emulator.x86emulator import x86Instruction, x86Emulator`
2. Copy source code of `emulator/x86emulator.py` and paste right in a new line after the last `import` in `smartchainer-standalone.py`

Done! 
