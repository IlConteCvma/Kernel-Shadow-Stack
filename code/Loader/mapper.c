#include <elf.h>
#include <errno.h>
#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <arpa/inet.h>

#include <include.h>

#define ELF_ARCH   ELFCLASS64
#define ELFDATA_NATIVE  ELFDATA2LSB

#define PAGE_FLOOR(addr) ((addr) & (-PAGE_SIZE))                // Lower bound to page size
#define PAGE_CEIL(addr) (PAGE_FLOOR((addr) + PAGE_SIZE - 1))    // Upper bound to page size


// Sanity Check
bool is_compatible_elf(const ElfW(Ehdr) *ehdr) {
    return (ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
            ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
            ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
            ehdr->e_ident[EI_MAG3] == ELFMAG3 &&
            ehdr->e_ident[EI_CLASS] == ELF_CLASS &&
            ehdr->e_ident[EI_DATA] == ELFDATA_NATIVE);
}

void map(unsigned char *data, struct elf_info *md) {
    ElfW(Ehdr) *ehdr;
    ElfW(Phdr) *phdr;

    size_t virtual_offset = 0, total_to_map = 0, success = 0;
    unsigned char *mapping = MAP_FAILED;


    ehdr = (ElfW(Ehdr) *)data;
    phdr = (ElfW(Phdr) *)(data + ehdr->e_phoff);

    // Compute only necessary memory (only PT_LOAD size)
    total_to_map = compute_total_memory_size(ehdr, phdr);


    phdr = (ElfW(Phdr) *)(data + ehdr->e_phoff); // Reset pointer to first PT
    mapping = setup_memory(data, total_to_map, phdr, &virtual_offset, ehdr, md);
    if (mapping == MAP_FAILED){
        md->ehdr = MAP_FAILED;
        return;
    }

    // Write and protect segments
    success = map_segments(mapping, data, phdr, virtual_offset, total_to_map, ehdr, md);
    if (success == -1){
        munmap(mapping, total_to_map);
    }
}

size_t compute_total_memory_size(const ElfW(Ehdr) *ehdr, const ElfW(Phdr) *phdr) {
    size_t total_to_map = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            size_t segment_size = phdr[i].p_vaddr + phdr[i].p_memsz;
            total_to_map = (segment_size > total_to_map) ? segment_size : total_to_map;
        }
    }

    dprint("Necessary to allocate %08zx\n", total_to_map);
    return total_to_map;
}

// Setup area in memory to contain the new binary image
unsigned char *setup_memory(unsigned char *data, size_t total_to_map, ElfW(Phdr) *phdr, size_t *virtual_offset, ElfW(Ehdr) *ehdr, struct elf_info *md) {
    unsigned char *mapping = MAP_FAILED;


    for (int ii = 0; ii < ehdr->e_phnum; ii++, phdr++) {
        if (phdr->p_type == PT_LOAD) {


            if (mapping == MAP_FAILED) {        // First iteration will always be MAP_FAILED
                
                
                mapping = mmap((void *)PAGE_FLOOR(phdr->p_vaddr), PAGE_CEIL(total_to_map), PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
                if (mapping == MAP_FAILED) {
                    dprint("Failed to mmap(): %s\n", strerror(errno));
                    break;
                }
                dprint("Mapped %08zx of memory starting from %08zx\n", total_to_map, phdr->p_vaddr);

                memset(mapping, 0, total_to_map);
                
                /*
                * Position Indipendent Executable have not a virtual address on the first PHDR.
                * From 2nd program header, they have v_addr relative to the first PHDR (see readelf -l examples/homemade/hello_world)
                * Also each field of EHDR is relative to where the file will be put in memory
                */
               if (phdr->p_vaddr == 0){
                    *virtual_offset = (size_t) mapping;
                }

                // First program header contains EHDR    
                md->ehdr = (ElfW(Ehdr) *) mapping;

                // Retrive entry point to jmp
                md->entry_point = *virtual_offset + ehdr->e_entry;
            }
            // mmap was successful
            break;

        }
    }
    return mapping;
}

// Each segment will be mapped to vaddr so ther will be no conflicts and no needs of adjustments
size_t map_segments(unsigned char *mapping, unsigned char *data, ElfW(Phdr) *phdr, size_t virtual_offset, size_t total_to_map, ElfW(Ehdr) *ehdr, struct elf_info *md) {
    ElfW(Addr) dest = 0;
    const unsigned char *source = 0;
    size_t len;
    int prot;

    phdr = (ElfW(Phdr) *)(data + ehdr->e_phoff);
    for (int ii = 0; ii < ehdr->e_phnum; ii++, phdr++) {
        if (phdr->p_type == PT_LOAD) {
            source = data + phdr->p_offset;

            // If PIE we need to put each PHD at v_addr bytes from the start of the file in memory
            // If not PIE, virtual_offset is 0
            dest = virtual_offset + phdr->p_vaddr;
            len = phdr->p_filesz;

            memcpy((void *)dest, source, len);

            prot = (((phdr->p_flags & PF_R) ? PROT_READ : 0) |
                    ((phdr->p_flags & PF_W) ? PROT_WRITE: 0) |
                    ((phdr->p_flags & PF_X) ? PROT_EXEC : 0));
            if (mprotect((void *)PAGE_FLOOR(dest), PAGE_CEIL(phdr->p_memsz), prot) != 0) {
                return -1;
            }
        } else if (phdr->p_type == PT_INTERP) {
            dprint("Found PT_INTERP\n");
            md->interp = (char *) phdr->p_offset;      // Only store offset, see below
        }
    }

    if (md->interp) {
        // The intepreter will be mapped after malicious ELF
        // It must come before
        md->interp = (char *) mapping + (size_t) md->interp;
    }

    return 1;
}
s