# Oreans Demo VM Hooking

### Context Buffer
```cpp
#pragma pack(push, 1)
typedef struct _OREANS_BUFFER {
	unsigned short m_unV1;
	char _Pad1[8];
	unsigned int m_unV2;
	char _Pad2[3];
	unsigned char m_unV3;
	char _Pad3[1];
	unsigned int m_unV4;
	char _Pad4[24];
	unsigned int m_unV5;
	char _Pad5[12];
	unsigned int m_unV6;
	char _Pad6[42];
	unsigned short m_unV7;
	unsigned short m_unV8;
	char _Pad7[40];
	unsigned int m_unV9;
	char _Pad8[8];
	unsigned int m_unV10;
	char _Pad9[17];
	unsigned int m_unV11;
	char _Pad10[20];
	unsigned int m_unV12;
	unsigned int m_unV13;
} OREANS_BUFFER, *POREANS_BUFFER;
#pragma pack(pop)
```

### VM Demo Signature
```
void* oreans_demo_identifier = get_signature("55 8B EC 81 C4 BC FD FF FF 8D")

unsigned char* oreans_mov_pointer = reinterpret_cast<unsigned char*>(oreans_demo_identifier) + 0x1D;
-- Change VirtualProtect on oreans_mov_pointer of (size 1) to PAGE_READWRITE
-- set oreans_mov_pointer[0] to 0 to clear the mov
oreans_mov_pointer[0] = 0;
-- Change VirtualProtect on oreans_mov_pointer to unprotect (restore)

typedef void(__stdcall* vm_function_t)(unsigned char, unsigned int*);
oreans_vmcall_pointer = reinterpret_cast<unsigned char*>(oreans_demo_identifier) + 0x10;
vm_function = reinterpret_cast<vm_function_t>(reinterpret_cast<unsigned int>(oreans_vmcall_pointer) + sizeof(unsigned int) + (*reinterpret_cast<unsigned int*>(oreans_vmcall_pointer)));
```

### VM Demo Signature Hook
```cpp
void __stdcall oreans_vm_hook(unsigned char vm_index, unsigned int* vm_data) {
	switch (vm_index) {
		case 0x01: { // Check executable headers
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x02: { // MAP list
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x03: { // MAP list
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x04: { // MAP list
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x05: { // MAP list
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x06: { // MAP list
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x07: { // MAP list (Viewer - Dissambler)
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x08: { // MAP list (Viewer - Dissambler)
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x09: { // MAP list
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x0A: { // First initialization
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x0B: { // Get VMs Names
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x0D: { // Get VMs Complexity
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x0E: { // Get VMs Speeds
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x0F: { // Get VMs Sizes
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x10: { // Get VMs
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x16: { // MAP list
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x17: { // MAP list
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x19: { // MAP list
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x1B: { // Get protection macroses
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x1C: { // Unknown
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x1D: { // Unknown initialization
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x20: { // Unknown (Called when loadinging file)
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x21: { // Unknown (Called when loadinging file)
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x22: { // Unknown (Called when loadinging file)
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x23: { // Unknown (Called when loadinging file)
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x24: { // Unknown (Called when loadinging file)
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x25: { // Macros processor
			unsigned int vm_macro_index = vm_data[0];
			unsigned int* vm_macro_data = reinterpret_cast<unsigned int*>(vm_data[13]);
			switch (vm_macro_index) {
				case 0x3A: { // Checking Input and Output files
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x4C: { // Stealth...
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x4D: { // Stealth...
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x05: { // Reading Protection Macros
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x16: { // Reading Protection Macros
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x4F: { // Initializing VM machines
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x5D: { // Ansi Strings to Virtualize
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x68: { // Ansi Strings to Virtualize
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x5F: { // Ansi Strings to Virtualize
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x5E: { // Unicode Strings to Virtualize
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x69: { // Unicode Strings to Virtualize
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x60: { // Unicode Strings to Virtualize
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x2A: { // Virtual Machines Generation
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x15: { // Virtual Machines Generation
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x10: { // Virtual Machines Generation
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x12: { // Virtual Machines Generation
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x11: { // Virtual Machines Generation
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x14: { // Virtual Machines Generation
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x2C: { // Potecting Macros (Mutation & StrEncrypt)
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x2D: { // Potecting Macros (Mutation & StrEncrypt)
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x62: { // Potecting Macros (Mutation & StrEncrypt)
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x63: { // Potecting Macros (Mutation & StrEncrypt)
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x64: { // Potecting Macros (Virtualization)
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x08: { // Compressing Virtual Machines
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x2F: { // Compressing Virtual Machines
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x32: { // Compressing Virtual Machines
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x57: { // Finalizing Protection
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x44: { // Taggant
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x45: { // Taggant
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x43: { // Taggant
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x6D: { // Code Signing
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x6E: { // Code Signing
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x41: { // Unknown
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x17: { // Unknown
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x1C: { // Unknown
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x6B: { // Unknown
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x58: { // Unknown
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x59: { // Unknown
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x18: { // Unknown
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x1A: { // Unknown
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x1B: { // Unknown
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x65: { // Called when Cancel pressed
					vm_function(vm_index, vm_data);
					return;
				}
				case 0x4E: { // Rebuilding?
					vm_function(vm_index, vm_data);
					return;
				}

				default: {
					printf("[+] Macro (ID=0x%02X)\n", vm_macro_index);
					printf("[+] Data: %08X (%08X)\n", vm_macro_data, *vm_macro_data);
					vm_function(vm_index, vm_data);
					return;
				}
			}
			return;
		}
		case 0x26: { // Get VMs
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x2F: { // Unknown (Called when loadinging file)
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x32: { // Unknown (Called when loadinging file)
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x33: { // Unknown (Called when loadinging file)
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x34: { // Unknown (Called when loadinging file)
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x35: { // Unknown
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x36: { // License Info
			// vm_data[10] = reinterpret_cast<unsigned int>(L"Name of the License Owner");
			return;
		}
		case 0x37: { // License Info
			// vm_data[10] = reinterpret_cast<unsigned int>(L"Name of the License Owner (Company)");
			return;
		}
		case 0x38: { // License Info Key
			// vm_data[10] = reinterpret_cast<unsigned int>(L"1234-1234-1234-1234");
			return;
		}
		case 0x3C: { // Is Demo Flag
			// vm_data[7] = 0;
			return;
		}
		case 0x46: { // Unknown
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x47: { // MAP list
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x12: { // Unknown
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x43: { // Unknown
			vm_function(vm_index, vm_data);
			return;
		}
		case 0x30: { // Unknown
			vm_function(vm_index, vm_data);
			return;
		}
		default: {
			vm_function(vm_index, vm_data);

			printf("[+] VM (ID=0x%02X) from 0x%08X (RVA: 0x%08X)\n", vm_index, (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)base_address);
			printf("[+] Data: ");
			for (unsigned char i = 0; i < 14; ++i) {
				printf("%08X ", vm_data[i]);
			}
			printf("\n");

			return;
		}
	}
	return;
}
```
