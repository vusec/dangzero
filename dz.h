#ifndef DANGZERO_H
#define DANGZERO_H
#define LOG(...) //printf(__VA_ARGS__)
#define LIKELY(COND) __builtin_expect((COND), 1)
#define UNLIKELY(COND) __builtin_expect((COND), 0)
#define PAGE_SIZE 4096

#define __GC
#define __GC_PT_COMPRESS
//#define __GC_WATERMARK (10000000ULL) // pages
#define NUM_BUCKETS 10000
#define WM_ALLOC(sz) kmalloc(sz, GFP_NOWAIT)
//#define WM_ALLOC(sz) __libc_malloc(sz) 
#define WM_FREE(ptr) kfree(ptr)
//#define WM_FREE(ptr) __libc_free(ptr)
//#define WM_ZERO

// regular malloc for WM is useful for memory overhead measurements

//#define __PT_RECLAIM

//#define __TRACK_SHADOW_SIZE
#define OUTPUT_FREQ 100000 // every n allocs output shadow sz

//#define __TRACK_MEM_USAGE
//#define __SANITY_CHECK
#define __ENABLE_FORK_SUPPORT

// page table indexing
#define PAGE_MASK (~(PAGE_SIZE-1)) // to disable the page flags (e.g. 0x20d4067 -> 0x20d4000)
#define PAGE_FRAME 0x000ffffffffff000UL
#define PAGE_MASK_INDEX 0x1FF // 511
#define MAX_PAGE_INDEX 511
#define PML4_INDEX(x)	((x >> 39) & PAGE_MASK_INDEX)
#define PDPT_INDEX(x)	((x >> 30) & PAGE_MASK_INDEX)
#define PDE_INDEX(x)	((x >> 21) & PAGE_MASK_INDEX)
#define PTE_INDEX(x)	((x >> 12) & PAGE_MASK_INDEX)

#define PML4_ADDR_OFFSET 0x8000000000
#define PDPT_ADDR_OFFSET 0x40000000
#define PDE_ADDR_OFFSET 0x200000

// arch/x86/include/asm/pgtable_types.h
#define PAGE_PRESENT 1
#define PAGE_WRITABLE 2
#define PAGE_DIRTY (1 << 6)
#define PAGE_HUGE (1 << 7)

// arch/x86/include/asm/page_64_types.h:
#define PAGE_OFFSET		0xffff880000000000UL
#define __START_KERNEL_map	0xffffffff80000000UL
typedef uint64_t phys_addr_t;

/*
> the gap for direct mapping of all physical memory is 64TB
> that is: 0xffff888000000000 ~ 0xffffc87fffffffff
> the corresponding PML4s are entries 273 ~ 400
> note that PML4E 272 is used for the guard hole for hypervisor (and seems present on QEMU)
> assuming the system uses 27 x 512 GB physical memory at most (which is insane)
> we start our shadow mapping at PML4E 300 (300 << 39 == 0xffff960000000000)
> and it ends including PML4E 400 (0xffffc87fffffffff)
> this gives us a little over 50 TB of PT shadow space (about 12.5 billion shadow pages)
*/
#define PML4_SHADOW_START 300
#define PML4_SHADOW_END 400
#define SHADOW_BASE 0xffff960000000000
#define SHADOW_END 0xffffc88000000000 //0xffffc87fffffffff

void* __libc_malloc(size_t size);
void* __libc_calloc(size_t nmemb, size_t size);
void* __libc_realloc(void* ptr, size_t size);
void* __libc_memalign(size_t alignment, size_t size);
void* __libc_free(void* ptr);
#ifdef __ENABLE_FORK_SUPPORT
pid_t __libc_fork(void);
#endif

// monica vm
// kernel function symbols (obtained through command "nm vmlinux" or "sudo cat /proc/kallsyms"
/*#define SYMBOL_ADDR_get_zeroed_page 0xffffffff811131a0
#define SYMBOL_ADDR_free_pages 0xffffffff81115bc0
#define SYMBOL_ADDR___get_free_pages 0xffffffff81113160
#define SYMBOL_ADDR_kallsyms_lookup_name 0xffffffff810bd350
#define SYMBOL_ADDR_kfree 0xffffffff811593c0
#define SYMBOL_ADDR_kmalloc 0xffffffff81159070
*/

#define SYMBOL_ADDR_get_zeroed_page 0xffffffff811635d0//0xffffffff811131a0
#define SYMBOL_ADDR_free_pages 0xffffffff81166480//0xffffffff81115bc0
#define SYMBOL_ADDR___get_free_pages 0xffffffff81163580//0xffffffff81113160
#define SYMBOL_ADDR_kallsyms_lookup_name 0xffffffff810e3870//0xffffffff810bd350
#define SYMBOL_ADDR_kfree 0xffffffff811b4b40//0xffffffff811593c0
#define SYMBOL_ADDR_kmalloc 0xffffffff811b5c40

// dangzero kernel module
typedef struct map_pa_va* (*proto_dangzero_create_fork_map)(uintptr_t* cr3, size_t* n);
proto_dangzero_create_fork_map dangzero_create_fork_map;

// kernel functions
typedef unsigned long (*proto_get_zeroed_page)(unsigned int);
typedef void (*proto_free_pages)(unsigned long addr, unsigned int order);
typedef unsigned long (*proto___get_free_pages)(unsigned mask, unsigned int order);
typedef void (*proto_kfree)(const void*);
typedef void* (*proto_kmalloc)(size_t size, unsigned flag);
// include/linux/kallsyms.h
typedef unsigned long (*proto_kallsyms_lookup_name)(const char* name);

// linux-4.0/include/linux/gfp.h
#define GFP_NOWAIT 0
#define GFP_KERNEL 208

// arch/x86/include/asm/io.h:
// only valid to use this function on addresses directly mapped or allocated via kmalloc
static phys_addr_t virt_to_phys(volatile void* address)
{
	return (phys_addr_t)address - PAGE_OFFSET;
}

static void* phys_to_virt(phys_addr_t address)
{
	return (void*)(address + PAGE_OFFSET);
}

#ifdef __GC
struct vp_span {
    uint64_t start;
    uint64_t end;
    bool last_sync; // page walk optimization
    LIST_ENTRY(vp_span) freelist;
};

struct vp_freelist {
    // Singly-linked list of vp_span objects, ordered by span->end (ascending)
    LIST_HEAD(, vp_span) items;
};

//uint64_t freelist_size();
int freelist_free(struct vp_freelist *list, void *p, size_t npages);
struct vp_span *try_merge_spans(struct vp_span *left, struct vp_span *right);
#endif


#ifdef __TRACK_SHADOW_SIZE
void output_shadow_size(bool gc); 
#endif
uintptr_t* create_page_table(uintptr_t* table, unsigned short entry);
static uintptr_t* get_table_page(uintptr_t* table, unsigned short index);
static uintptr_t* get_table_page_nocheck(uintptr_t* table, unsigned short index);
phys_addr_t get_phys_addr_user(uintptr_t addr);
#ifdef __GC_PT_COMPRESS
uintptr_t* step_shadow_table_L2cpt(uintptr_t* table, unsigned short index);
#endif
uintptr_t* step_shadow_table(uintptr_t* table, unsigned short index);
void disable_shadow_one(uintptr_t addr);
void disable_shadows(uintptr_t base, size_t num_pages);
uintptr_t* create_shadow_one(uintptr_t canon, size_t offset);
uintptr_t* create_shadows(uintptr_t canon, size_t num_pages, size_t offset);

#endif
