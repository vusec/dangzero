#ifndef DANGLESS_GC_H
#define DANGLESS_GC_H
#include <stdbool.h>

// temp
uint64_t out_cpt_list_size();

enum pt_level {
  PT_INVALID = 0,

  PT_L1 = 1,
  PT_4K = PT_L1,

  PT_L2 = 2,
  PT_2M = PT_L2,

  PT_L3 = 3,
  PT_1G = PT_L3,

  PT_L4 = 4,
  PT_512G = PT_L4,

  PT_NUM_LEVELS = PT_L4
};

enum {
  PT_BITS_PER_LEVEL = 9u,

  PT_NUM_ENTRIES = 1uL << PT_BITS_PER_LEVEL,
};

enum {
  PGSHIFT = 12u,
  PGSIZE = 1uL << PGSHIFT
};

enum pte_flags {
  // Flags as defined by the architecture
  PTE_P   = 1UL << 0, // present
  PTE_W   = 1UL << 1, // writable
  PTE_U   = 1UL << 2, // user accessible
  PTE_PWT = 1UL << 3, // write-through
  PTE_PCD = 1UL << 4, // cache-disable
  PTE_A   = 1UL << 5, // accessed
  PTE_D   = 1UL << 6, // dirty
  PTE_PS  = 1UL << 7, // page-size (in L2/L3)
  PTE_G   = 1UL << 8, // global
  // bits 9..11 ignored
  // bits 12..51 page frame/reserved
  // bits 52..62 ignored
  PTE_NX  = 1UL << 63, // non-executable

  // Flags used by dangless (should be ignored bits in arch, although most are
  // only set on non-present PTEs generally)
  PTE_ALIASSES    = 1UL << 8,  // child levels are aliasses (>L1, !PS)
  PTE_INVALIDATED = 1UL << 9,  // invalidated alias (L1..L4)
  PTE_OBJEND      = 1UL << 10, // object ends at this page (L1)
  PTE_MARKED      = 1UL << 62, // marked (GC) (L1..L4)

  // Entries pointing to compressed page tables have some more constraints, only
  // the lower 6 bits are not used for the cpt pointer. Only valid if !PTE_P.
  PTE_COMPRESSED   = 1UL << 1, // points to compressed L1PT (2bit cpt) (L2)
  PTE_CMS_ONEBIG   = 1UL << 3, // cpt consists of 1 obj (no cptp)
  PTE_CMS_ALLSMALL = 1UL << 4, // cpt consists of all 4K objs (no cptp)
};

enum {
    PTE_EMPTY = 0,
};

enum {
  PTE_FRAME_CPT = 0x000fffffffffffc0UL,

  PTE_FRAME     = 0x000ffffffffff000UL,
  PTE_FRAME_4K  = PTE_FRAME,
  PTE_FRAME_L1  = PTE_FRAME_4K,

  PTE_FRAME_2M  = 0x000fffffffe00000UL,
  PTE_FRAME_L2  = PTE_FRAME_2M,

  PTE_FRAME_1G  = 0x000fffffc0000000UL,
  PTE_FRAME_L3  = PTE_FRAME_1G,

};

typedef void cpt_t; /* Disallow derefs without explicit cast. */
enum compression_type {
    COMPRESSION_NONE     = 0,
    COMPRESSION_NORMAL   = 1,
    COMPRESSION_ONEBIG   = 2,
    COMPRESSION_ALLSMALL = 3,
};

enum cpt_field {
    CPT_OBJEND      = 0UL,
    CPT_INVALIDATED = 1UL,

    CPT_NUM_FIELDS  = 2UL
};

#define CPT_SIZE_BITS (PT_NUM_ENTRIES * CPT_NUM_FIELDS)
#define CPT_SIZE_BYTES (CPT_SIZE_BITS / 8)

#define CPT_SLAB_PAGES (1)
#define CPT_SLAB_SIZE (CPT_SLAB_PAGES * PGSIZE)

typedef int8_t i8;
typedef uint8_t u8;
typedef int16_t i16;
typedef uint16_t u16;
typedef int32_t i32;
typedef uint32_t u32;
typedef int64_t i64;
typedef uint64_t u64;
typedef u64 pte_t;
typedef uintptr_t paddr_t;
typedef uintptr_t vaddr_t;

#define PG_OFFSET(BASE, NPAGES) \
  ((typeof((BASE)))((uintptr_t)(BASE) + (NPAGES) * PGSIZE))

#define FLAG_ISSET(BITSET, BIT) ((bool)((BITSET) & (BIT)))

typedef int (*proto_dangzero_find_vma_bounds)(uintptr_t ptr, uintptr_t* start, uintptr_t* end);
proto_dangzero_find_vma_bounds dangzero_find_vma_bounds;
typedef void (*proto_dangzero_mark_heap)(void* func_mark_ptr);
proto_dangzero_mark_heap dangzero_mark_heap;

static inline bool pte_is_compressed(pte_t pte, enum pt_level level)
{
    return level == PT_L2 && !(pte & PTE_P) && (pte & PTE_COMPRESSED);
}

void cpt_nuke(void);
void cpt_destruct(void);
pte_t* uncompress_pte(enum pt_level level, pte_t *pte);
void try_collect_pt(vaddr_t va, size_t npages);
void try_compress_pt(vaddr_t va, size_t npages);
void gc_run(void);
void gc_init(void);

#endif
