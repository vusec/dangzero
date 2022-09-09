/*
 * Collector for freed objects, to allow for reuse of virtual addresses in alias
 * space.
 *
 * We scan all alive memory (regs, stack, data, alive heap objects) for (things
 * that look like) pointers to the aliassed heap during the marking phase.
 * Then we perform a sweep where each object that was freed and not marked is
 * given back to the alias allocator for reuse.
 *
 * We reuse the page tables as data structures for GC administration (e.g.,
 * marking).
 *
 * Originally created by Koen Koning (Dangless project)
 */

#include <sys/time.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

//#define NDEBUG // disable assertions
#include <assert.h>	
#define ASSERT0 assert

#include "queue.h"
#include "dz.h"
#include "gc.h"

#ifdef __GC
extern uintptr_t* g_cr3;
extern proto___get_free_pages __get_free_pages;
extern proto_free_pages free_pages;
extern uint64_t highest_shadow;
extern struct vp_freelist* g_freelist;
extern uint64_t bucket_size;
extern bool fragmented;
//extern unsigned curr_bucket;
extern struct vp_freelist *opt_freelist;
extern struct vp_span **sub_spans;
extern proto_kfree kfree;
extern proto_kmalloc kmalloc;

#ifdef __TRACK_MEM_USAGE
extern uint64_t max_pt_count;
extern uint64_t curr_pt_count;
#endif

/* dangless functionality re-implemented */
static cpt_t *cpt_freelist;

static inline unsigned pt_level_shift(enum pt_level level) {
  return PGSHIFT + (level - 1) * PT_BITS_PER_LEVEL;
}

static inline size_t pt_level_offset(vaddr_t va, enum pt_level level) {
  return (va >> pt_level_shift(level)) & (PT_NUM_ENTRIES - 1);
}

static inline u64 rcr3(void) {
  return (u64)g_cr3;
}

void *pt_paddr2vaddr(paddr_t pa) {
    return phys_to_virt(pa);
}
/* Upper 16 bits of addresses are sign-extended. */
static inline vaddr_t sext(vaddr_t va)
{
    if (va & (1UL << 47))
        va |= 0xffff800000000000UL;
    return va;
}
// Calculates the number of 4K pages mapped by an entry at the given pagetable level.
static inline size_t pt_num_mapped_pages(enum pt_level level) {
  return 1uL << ((level - 1) * PT_BITS_PER_LEVEL);
}
/* end of dangless re-implemented */


static uintptr_t stack_top;
static uintptr_t bss_start, bss_end;
static uintptr_t data_start, data_end;

/*
 * Generate variables in data and bss mappings so we can scan for their
 * addresses in proc maps.
 */
static int bss_seg_var = 0;
static int data_seg_var = 1;


static uintptr_t get_stack_pointer(void)
{
    uintptr_t rsp;
    asm ("mov %%rsp, %0" : "=r"(rsp));
    return rsp;
}

static inline bool is_potential_ptr(uintptr_t v)
{
   return SHADOW_BASE <= v && v <= SHADOW_END;
}

///// reclaiming (non-gc) /////
int pt_is_collectable(pte_t *pt)
{
    unsigned pte_idx;

    for (pte_idx = 0; pte_idx < PT_NUM_ENTRIES; pte_idx++)
        if (!(pt[pte_idx] & PTE_INVALIDATED))
            return 0;

    return 1;
}

static unsigned try_collect_pt_rec(vaddr_t va,
                                   vaddr_t va_end,
                                   enum pt_level level,
                                   pte_t *pt)
{
    pte_t *ppte, *nextpt;
    size_t ptoff;
    paddr_t nextpt_pa;
    unsigned freed = 0, next_freed;

    vaddr_t va_level_next, va_level_end;
    size_t level_inc = 1UL << pt_level_shift(level);

    if (level == PT_L1) {
        //LOG("pt%d %p \n", level, pt);
        return 1;
    }

    while (va < va_end) {
        ptoff = pt_level_offset(va, level);
        va_level_next = (va + level_inc) & ~(level_inc - 1);
        va_level_end = va_end < va_level_next ? va_end : va_level_next;

        ppte = &pt[ptoff];
        //LOG("pt%d va=%p pt=%p off=%zx pte=%lx\n", level, va, pt, ptoff, *ppte);
        if (!FLAG_ISSET(*ppte, PTE_P) || FLAG_ISSET(*ppte, PTE_PS))
            return 0;

        nextpt_pa = *ppte & PTE_FRAME;
        nextpt = (pte_t*)pt_paddr2vaddr(nextpt_pa);

        next_freed = try_collect_pt_rec(va, va_level_end, level - 1, nextpt);

        if (next_freed == 512 ||
                (next_freed > 0 && pt_is_collectable(nextpt))) {
            //LOG(" ########## pt%d empty, freeing %lx in pte %p\n", level - 1,
            //    nextpt_pa, ppte);
            //virtual_invalidate_pte(ppte);
	    *ppte = PTE_INVALIDATED | PTE_ALIASSES;

	    //pp_free_one(nextpt_pa);
	    free_pages((unsigned long)nextpt, 0);
#ifdef __TRACK_MEM_USAGE
	    curr_pt_count--;
#endif
            freed++;

	    //STATISTIC_UPDATE() {
            //    st_num_pagetables_collected++;
            //}
        }
        va = va_level_next;

        //LOG("pt%d next va=%p end=%p next_freed=%u freed=%u\n", level, va, va_end, next_freed, freed);

    }

    return freed;
}

void try_collect_pt(vaddr_t va, size_t npages)
{
    vaddr_t va_end = PG_OFFSET(va, npages);
    pte_t *ptroot = (pte_t*)g_cr3;
    //LOG("Collecting %lx - %lx (%zx pages)\n", va, va_end, npages);
    try_collect_pt_rec(va, va_end, PT_L4, ptroot);
}


///// compression /////
static inline size_t cpt_bitnum_to_wordidx(size_t bitnum)
{
    ASSERT0(bitnum < CPT_SIZE_BITS);
    return bitnum / (sizeof(uintptr_t) * 8);
}
static inline size_t cpt_bitnum_to_wordbit(size_t bitnum)
{
    ASSERT0(bitnum < CPT_SIZE_BITS);
    return bitnum % (sizeof(uintptr_t) * 8);
}
static inline bool cpt_get_bit(cpt_t *cpt, size_t bitnum)
{
    ASSERT0(bitnum < CPT_SIZE_BITS);
    uintptr_t *cpt_words = (uintptr_t *)cpt;
    uintptr_t word = cpt_words[cpt_bitnum_to_wordidx(bitnum)];
    return (word >> cpt_bitnum_to_wordbit(bitnum)) & 1;
}

static inline void cpt_set_bit(cpt_t *cpt, size_t bitnum, bool val)
{
    ASSERT0(bitnum < CPT_SIZE_BITS);
    ASSERT0(val == 0 || val == 1);
    uintptr_t *cpt_words = (uintptr_t *)cpt;
    uintptr_t *wordp = &cpt_words[cpt_bitnum_to_wordidx(bitnum)];
    size_t bitpos = cpt_bitnum_to_wordbit(bitnum);
    *wordp = (*wordp & ~(1UL << bitpos)) | ((uintptr_t)val << bitpos);
}

bool cpt_get_entry(cpt_t *cpt, size_t idx, enum cpt_field field)
{
    ASSERT0(idx < PT_NUM_ENTRIES);
    ASSERT0(field < CPT_NUM_FIELDS);
    return cpt_get_bit(cpt, idx * CPT_NUM_FIELDS + field);
}

void cpt_set_entry(cpt_t *cpt, size_t idx, enum cpt_field field, bool val)
{
    ASSERT0(idx < PT_NUM_ENTRIES);
    ASSERT0(field < CPT_NUM_FIELDS);
    cpt_set_bit(cpt, idx * CPT_NUM_FIELDS + field, val);
}

// temp
/*uint64_t cpt_size = 0;
uint64_t out_cpt_list_size()
{
    return cpt_size;
}
*/

static void grow_cpt_freelist(void)
{
    char *pg;
    size_t i;

    ASSERT0(cpt_freelist == NULL);

    // allocate CPT_SLAB_PAGES pages (== 1 right now, so order 0)
    pg = (char *)__get_free_pages(GFP_NOWAIT, 0); // ptpa = pp_zalloc_one();
    // memset((void*)pt, 0, PAGE_SIZE);

#ifdef __TRACK_MEM_USAGE
    curr_pt_count++;
    if(curr_pt_count > max_pt_count){
        max_pt_count = curr_pt_count;
    }
#endif

    // pg = (char *)pp_alloc(CPT_SLAB_PAGES);
    // if (!pg) {
    //     vdprintf_nomalloc("Could not allocate cpt page\n");
    //     _dangless_assert_fail();
    // }

    for (i = 0; i + CPT_SIZE_BYTES < CPT_SLAB_SIZE; i += CPT_SIZE_BYTES) {
        cpt_t **cpt = (cpt_t **)&pg[i];
        *cpt = cpt_freelist;
        cpt_freelist = cpt;
	// temp
	//cpt_size++;
    }
}

cpt_t *cpt_alloc(void)
{
    void *ret;

    if (!cpt_freelist)
        grow_cpt_freelist();

    ret = cpt_freelist;
    cpt_freelist = *((cpt_t **)cpt_freelist);
	// temp
	//cpt_size--;

    //LOG("cpt alloc: %lx\n", ret);
    return ret;
}

void cpt_free(cpt_t *cpt)
{
    *((cpt_t **)cpt) = cpt_freelist;
    cpt_freelist = cpt;

	// temp
	//cpt_size++;

    /* TODO: give back fully freed cpt pages to physmem allocator.
     * how do we do this? We'd need per-page or per slab metadata... and
     * a doubly-linked list to remove arbitrary entries. */
}

void cpt_destruct(void)
{
    // free the pages in the compression freelist
    cpt_t* curr;
    while(cpt_freelist != NULL){
        curr = cpt_freelist;
	cpt_freelist = *((cpt_t **)cpt_freelist);
	
	if( ((uintptr_t)curr & 0xfff) == 0){ // page-aligned
	    free_pages((unsigned long)curr, 0);
	}
    }
}

void cpt_nuke(void)
{
    cpt_freelist = NULL;
}

void uncompress_cpt_to_pt(cpt_t *cpt, pte_t *pt)
{
    size_t i;

    for (i = 0; i < PT_NUM_ENTRIES; i++) {
        pt[i] = PTE_EMPTY;
        if (cpt_get_entry(cpt, i, CPT_OBJEND))
            pt[i] |= PTE_OBJEND;
        if (cpt_get_entry(cpt, i, CPT_INVALIDATED))
            pt[i] |= PTE_INVALIDATED;
    }
}

pte_t* uncompress_pte(enum pt_level level, pte_t *pte)
{
    paddr_t ptpa;
    pte_t *pt;
    size_t i;

    (void)level;
    ASSERT0(level == PT_L2);
    ASSERT0(pte_is_compressed(*pte, level));

    pt = (pte_t*)__get_free_pages(GFP_NOWAIT, 0); // ptpa = pp_zalloc_one();
    memset((void*)pt, 0, PAGE_SIZE);
    if (!pt) {
        printf("failed to allocate pagetable page!\n");
        return NULL;
    }

#ifdef __TRACK_MEM_USAGE
    curr_pt_count++;
    if(curr_pt_count > max_pt_count){
        max_pt_count = curr_pt_count;
    }
#endif

    ptpa = virt_to_phys(pt); // pt = pt_paddr2vaddr(ptpa);

    if ((*pte & PTE_CMS_ONEBIG) || (*pte & PTE_CMS_ALLSMALL)) {
        //LOG("Uncompressing compact PTE %lx\n", *pte);
        pte_t pte_bits = PTE_INVALIDATED;
        if (*pte & PTE_CMS_ALLSMALL)
            pte_bits |= PTE_OBJEND;

        for (i = 0; i < PT_NUM_ENTRIES; i++)
            pt[i] = pte_bits;
    } else {
        cpt_t *cpt = (cpt_t *)((*pte & PTE_FRAME_CPT) + PAGE_OFFSET);
        //LOG(" uncompressing cpt %p to pt %p\n", cpt, pt);
        uncompress_cpt_to_pt(cpt, pt);
        cpt_free(cpt);
    }

    *pte = (pte_t)ptpa | PTE_ALIASSES | PTE_NX | PTE_W | PTE_P;
    return pt;
}

void compress_pt_to_cpt(pte_t *pt, cpt_t *cpt)
{
    size_t i;

    for (i = 0; i < PT_NUM_ENTRIES; i++) {
        bool objend = !!(pt[i] & PTE_OBJEND);
        bool invalidated = !!(pt[i] & PTE_INVALIDATED);

        ASSERT0(!(pt[i] & PTE_P));

        cpt_set_entry(cpt, i, CPT_OBJEND, objend);
        cpt_set_entry(cpt, i, CPT_INVALIDATED, invalidated);
    }
}

static enum compression_type pt_is_compressable(pte_t *pt)
{
    unsigned pte_idx;
    unsigned num_objends = 0;

    for (pte_idx = 0; pte_idx < PT_NUM_ENTRIES; pte_idx++) {
        if (!(pt[pte_idx] & PTE_INVALIDATED))
            return COMPRESSION_NONE;
        if (pt[pte_idx] & PTE_OBJEND)
            num_objends++;
    }

    if (num_objends == 0)
        return COMPRESSION_ONEBIG;
    else if (num_objends == PT_NUM_ENTRIES)
        return COMPRESSION_ALLSMALL;
    else
        return COMPRESSION_NORMAL;
}


static void try_compress_pt_rec(vaddr_t va,
                                vaddr_t va_end,
                                enum pt_level level,
                                pte_t *pt)
{
    const size_t level_inc = 1UL << pt_level_shift(level);
    vaddr_t va_level_next, va_level_end;
    pte_t *ppte, *nextpt;
    size_t ptoff;
    paddr_t nextpt_pa;

    ASSERT0(level > PT_L1);

    while (va < va_end) {
        ptoff = pt_level_offset(va, level);
        va_level_next = (va + level_inc) & ~(level_inc - 1);
        va_level_end = va_end < va_level_next ? va_end : va_level_next;

        ppte = &pt[ptoff];
        //LOG("pt%d va=%#lx pt=%p off=%zx pte=%lx\n", level, va, pt, ptoff, *ppte);
        if (!FLAG_ISSET(*ppte, PTE_P) || FLAG_ISSET(*ppte, PTE_PS))
            return;

        nextpt_pa = *ppte & PTE_FRAME;
        nextpt = (pte_t*)pt_paddr2vaddr(nextpt_pa);

        if (level > PT_L2)
            try_compress_pt_rec(va, va_level_end, level - 1, nextpt);
        else if (level == PT_L2) {
            enum compression_type type = pt_is_compressable(nextpt);
            if (type == COMPRESSION_NORMAL) {
                cpt_t *cpt = cpt_alloc();
                compress_pt_to_cpt(nextpt, cpt);

                //LOG(" ########## pt%d empty for va=%lx, compressing %lx to %p in pte %p\n",
                 //   level - 1, va, nextpt_pa, cpt, ppte);

                *ppte = (pte_t)virt_to_phys(cpt) | PTE_COMPRESSED;
                //LOG("New PTE: %lx\n", *ppte);
                //pp_free_one(nextpt_pa);
		free_pages((unsigned long)nextpt, 0);
#ifdef __TRACK_MEM_USAGE
	        curr_pt_count--;
#endif
            } else if (type == COMPRESSION_ONEBIG ||
                       type == COMPRESSION_ALLSMALL) {
                //LOG(" ########## pt%d very empty for va=%lx, compressing %lx to %s in pte %p\n",
                 //   level - 1, va, nextpt_pa, type == COMPRESSION_ONEBIG ? "ONEBIG" : "ALLSMALL", ppte);
                *ppte = PTE_COMPRESSED;
                if (type == COMPRESSION_ONEBIG)
                    *ppte |= PTE_CMS_ONEBIG;
                else if (type == COMPRESSION_ALLSMALL)
                    *ppte |= PTE_CMS_ALLSMALL;

                //pp_free_one(nextpt_pa);
		free_pages((unsigned long)nextpt, 0);
#ifdef __TRACK_MEM_USAGE
                curr_pt_count--;
#endif
            }
        }
        va = va_level_next;

        //LOG("pt%d next va=%p end=%p next_freed=%u freed=%u\n", level, va, va_end, next_freed, freed);

    }
}

// TODO do we ever need to compress pages with non-invalidated entries?
// i.e., compress fully invalidated ones, throw away fully reusable ones, leave
// mixed ones? we can also have 2 compressed formats
void try_compress_pt(vaddr_t va, size_t npages)
{
    vaddr_t va_end = PG_OFFSET(va, npages);
    pte_t *ptroot = (pte_t*)g_cr3;
    //LOG("==================================================================\n");
    //LOG("Compressing %lx - %lx (%zx pages)\n", va, va_end, npages);


    try_compress_pt_rec(va, va_end, PT_L4, ptroot);
}

///// marking /////
static int mark_ptr_rec(uintptr_t ptr, enum pt_level level, pte_t *pt);
int mark_ptr(uintptr_t ptr)
{
    int ret;
    //LOG("GC mark %#lx\n", ptr);
    ret = mark_ptr_rec(ptr, PT_L4, g_cr3);
    return ret;
}

static int mark_compressed_pte(uintptr_t ptr, enum pt_level level, pte_t *pte)
{
    pte_t *nextpt;
    pte_t *ret;

    ASSERT0(level == PT_L2);
    ASSERT0(pte_is_compressed(*pte, level));

    if (*pte & PTE_CMS_ONEBIG) {
        //LOG("Marking ONEBIG %lx\n", ptr);
        return 0; /* Leave compressed, mark_ptr_rec sets PTE_MARKED. */
    }

    ret = uncompress_pte(level, pte);
    if (ret == NULL)
        return -1;

    uintptr_t frame = *pte & PTE_FRAME;
    if(frame == 0) return 0;
    nextpt = (pte_t *)pt_paddr2vaddr(frame);
    mark_ptr_rec(ptr, level - 1, nextpt);
    return 0;
}

static int mark_ptr_rec(uintptr_t ptr, enum pt_level level, pte_t *pt)
{
    size_t ptoff;
    pte_t *pte, *nextpt;
    bool is_compressed = false;

    ptoff = pt_level_offset(ptr, level);
    pte = &pt[ptoff];

#ifdef __GC_PT_COMPRESS
    is_compressed = pte_is_compressed(*pte, level);
#endif

    /* Avoid creating page tables for areas we never allocated/invalidated. */
    if (level > PT_L1 && !(*pte & PTE_ALIASSES) && !is_compressed)
        return 0;

    /* Avoid needless setting/unsetting of marked bits. */
    if (level == PT_L1 && !(*pte & PTE_INVALIDATED))
        return 0;

    if (level > PT_L1) {
        ASSERT0(!(*pte & PTE_PS) || is_compressed);
        ASSERT0(!(*pte & PTE_INVALIDATED) || is_compressed);
#ifdef __GC_PT_COMPRESS
        if (is_compressed) {
            if (mark_compressed_pte(ptr, level, pte))
                return -1;
        } else 
#endif
	{
	    // for some reason *pte&frame == 0 is not caught
            uintptr_t frame = *pte & PTE_FRAME;
	    if(frame == 0) return 0;

            nextpt = (pte_t *)pt_paddr2vaddr(frame);
	    if (mark_ptr_rec(ptr, level - 1, nextpt))
                return -1;
        }
    }
	
    *pte |= PTE_MARKED;
    return 0;
}

static void mark_regs(void)
{
    size_t i;
    struct {
        unsigned long rax, rbx, rcx, rdx, rsi, rdi, rbp,
                      r8, r9, r10, r11, r12, r13, r14, r15;
    } regs;

#if 0
    char *regnames[] = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
                        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
#endif

    asm ("mov %%rax,   0(%0) \n\t"
         "mov %%rbx,   8(%0) \n\t"
         "mov %%rcx,  16(%0) \n\t"
         "mov %%rdx,  24(%0) \n\t"
         "mov %%rsi,  32(%0) \n\t"
         "mov %%rdi,  40(%0) \n\t"
         "mov %%rbp,  48(%0) \n\t"
         "mov %%r8,   56(%0) \n\t"
         "mov %%r9,   64(%0) \n\t"
         "mov %%r10,  72(%0) \n\t"
         "mov %%r11,  80(%0) \n\t"
         "mov %%r12,  88(%0) \n\t"
         "mov %%r13,  96(%0) \n\t"
         "mov %%r14, 104(%0) \n\t"
         "mov %%r15, 112(%0) \n\t"
         :
         : "r"(&regs)
         : "memory");

#if 0
    for (i = 0; i < sizeof(regs) / 8; i++)
        LOG(" %s: %016lx\n", regnames[i], ((unsigned long*)&regs)[i]);
#endif

    for (i = 0; i < sizeof(regs) / 8; i++) {
        uintptr_t v = ((uintptr_t*)&regs)[i];
        if (is_potential_ptr(v))
            mark_ptr(v);
    }
}

static void mark_stack(void)
{
    uintptr_t *sp, *top;

    sp = (uintptr_t *)get_stack_pointer();
    top = (uintptr_t *)stack_top;

    for (; sp < top; sp++) {
        if (is_potential_ptr(*sp)){
            mark_ptr(*sp);
	}
    }
}

static void mark_datasegs(void)
{
    /* TODO data/bss of libs? */

    uintptr_t *iter;

    for (iter = (uintptr_t*)bss_start; iter < (uintptr_t*)bss_end; iter++)
        if (is_potential_ptr(*iter))
            mark_ptr(*iter);

    for (iter = (uintptr_t*)data_start; iter < (uintptr_t*)data_end; iter++)
        if (is_potential_ptr(*iter))
            mark_ptr(*iter);
}


///////// sweeping /////////
static void rollback_invalidations_compressed(vaddr_t va,
                                              vaddr_t va_end,
                                              vaddr_t obj_end_va,
                                              cpt_t *cpt)
{
    size_t i, idx_start, idx_end, idx_obj_end;

    idx_start = pt_level_offset(va, PT_L1);
    idx_end = pt_level_offset(va_end, PT_L1);
    idx_obj_end = obj_end_va <= va_end ? pt_level_offset(obj_end_va, PT_L1)
                                       : PT_NUM_ENTRIES;
    if (idx_end == 0) idx_end = PT_NUM_ENTRIES;

    (void)idx_obj_end;
    //LOG("rbci %zu %zu (%zu)\n", idx_start, idx_end, idx_obj_end);

    for (i = idx_start; i < idx_end; i++) {
        //LOG("rbc idx=%zu objend=%zu\n", i, idx_obj_end);
        cpt_set_entry(cpt, i, CPT_INVALIDATED, 1);
    }
}

static void rollback_invalidations_rec(vaddr_t va,
                                       vaddr_t va_end,
                                       vaddr_t obj_end_va,
                                       enum pt_level level,
                                       pte_t *pt)
{
    const size_t level_inc = 1UL << pt_level_shift(level);
    vaddr_t va_level_next, va_level_end;
    pte_t *pte, *nextpt;

    while (va < va_end) {
        va_level_next = (va + level_inc) & ~(level_inc - 1);
        va_level_end = va_end < va_level_next ? va_end : va_level_next;
        pte = &pt[pt_level_offset(va, level)];

        //LOG("rb pt%d va=%#lx pte=%p *pte=%lx (nxt=%lx end=%lx)\n", level, va, pte, *pte, va_level_next, va_end);

        if (level > PT_L1 && !(*pte & PTE_P) && !pte_is_compressed(*pte, level)) {
            /* We (overoptimistically) cleared away an entire pgtable and need
             * to (re)allocate one. We know a cpt is always fine for this,
             * optionally we can use a ONEBIG entry. */
#ifdef __GC_PT_COMPRESS
            if (level > PT_L2) {
#else
            if (level >= PT_L2) {
#endif
		// NOTE: a rollback can never increase max mem usage curr_pt
                pte_t* temp_pt = (pte_t*)__get_free_pages(GFP_NOWAIT, 0); // paddr_t ptpa = pp_zalloc_one();
                memset((void*)temp_pt, 0, PAGE_SIZE);

#ifdef __TRACK_MEM_USAGE
		curr_pt_count++;
		if(curr_pt_count > max_pt_count){
    			max_pt_count = curr_pt_count;
		}
#endif

                paddr_t ptpa = virt_to_phys(temp_pt);
                ASSERT0(ptpa);
                *pte = (pte_t)ptpa | PTE_ALIASSES | PTE_NX | PTE_W | PTE_P;
            } else if (level == PT_L2) {
                if ((va & (level_inc - 1)) == 0 && va_level_end == va_level_next) {
                    *pte = PTE_CMS_ONEBIG;
                } else {
                    size_t i;
                    cpt_t *cpt = cpt_alloc();
                    for (i = 0; i < PT_NUM_ENTRIES; i++) {
                        cpt_set_entry(cpt, i, CPT_OBJEND, 0);
                        cpt_set_entry(cpt, i, CPT_INVALIDATED, 0);
                    }
                    //*pte = (pte_t)cpt | PTE_COMPRESSED;
		    *pte = (pte_t)virt_to_phys(cpt) | PTE_COMPRESSED;
                }
            }
        }

        if (level == PT_L1) {
             ASSERT0(*pte == PTE_EMPTY);
            *pte = PTE_INVALIDATED;
            if (va == obj_end_va)
                *pte = PTE_OBJEND;

        } else if (pte_is_compressed(*pte, level)) {
            ASSERT0(level == PT_L2);
            cpt_t *cpt = (void*)((*pte & PTE_FRAME_CPT) + PAGE_OFFSET);
            rollback_invalidations_compressed(va, va_level_end, obj_end_va,
                                              cpt);

        } else if (!(*pte & PTE_P) && (*pte & PTE_CMS_ONEBIG)) {
            ASSERT0(!(*pte & PTE_COMPRESSED));
            ASSERT0(!(*pte & PTE_MARKED));
            *pte |= PTE_COMPRESSED;

        } else {
            ASSERT0(*pte & PTE_P);
            nextpt = (pte_t*)pt_paddr2vaddr(*pte & PTE_FRAME);
            rollback_invalidations_rec(va, va_level_end, obj_end_va, level - 1,
                                       nextpt);
        }

        va = va_level_next;
    }
}

/*
 * During sweeping we optimistically undo the invalidation of PTEs, which we may
 * need to roll back later if one of the objects' pages was marked.
 */
void rollback_invalidations(vaddr_t start,
                            size_t npages_cleared,
                            size_t npages_total)
{
    vaddr_t va_end = PG_OFFSET(start, npages_cleared);
    vaddr_t obj_end_va = PG_OFFSET(start, npages_total);
    pte_t *ptroot = (pte_t*)g_cr3;

    //LOG("Reinvalidating %lx-%lx(-%lx)\n", start, va_end, obj_end_va);
    //fprintf(stderr, "ROLLBACK: %lx - %lx (end %lx)\n", start, va_end, obj_end_va);

    ASSERT0((start & (PGSIZE - 1)) == 0);
    ASSERT0(npages_cleared > 0);
    ASSERT0(npages_cleared <= npages_total);

    rollback_invalidations_rec(start, va_end, obj_end_va, PT_L4, ptroot);
}

static vaddr_t sweep_curobj_start, sweep_curobj_end;
static bool sweep_curobj_marked;
static size_t sweep_curobj_num_cleared;

static inline void sweep_curobj_reset(void)
{
    sweep_curobj_end = 0;
    sweep_curobj_marked = 0;
    sweep_curobj_num_cleared = 0;
}

static bool sweep_pt_rec(enum pt_level level, pte_t *pt,
                         size_t idx_start, size_t idx_end, vaddr_t partial_va);
static void sweep_all(void)
{
    pte_t *pt = (pte_t*)g_cr3;
    size_t ptoff_start = pt_level_offset(SHADOW_BASE, PT_L4);
    size_t ptoff_end = pt_level_offset(highest_shadow, PT_L4); // SHADOW_END

    if(ptoff_end == ptoff_start)
        ptoff_end++;

    LOG("sweep from pt: %p L4 ids: %lu %lu\n", pt, ptoff_start, ptoff_end);
    sweep_curobj_reset();
    sweep_pt_rec(PT_L4, pt, ptoff_start, ptoff_end, 0);
}

void cascade_bucket_ptrs(unsigned b, struct vp_span* old, struct vp_span* new)
{
	// upon merge-into-next, a bucket ptr can move
	// if other bucket ptrs pointed to the same span
	// they should move with, because the old-next gets freed
	// search left buckets is not needed 
	// smaller cannot share ptr
	
	// smaller buckets do not have to be searched,
	// since they cannot point to a larger bucket's span

	// the mega span
	if(old->end > highest_shadow){
		return;
	}
		
	// other bucket ptrs only relevant if the span is large enough
	unsigned end_bucket = ((old->end - SHADOW_BASE) / bucket_size); 

	// search right buckets
	for(unsigned s = b+1; b <= end_bucket; b++){
		if(sub_spans[s] != NULL){
			if(sub_spans[s] == old){
				sub_spans[s] = new;
			}
			else{
				// next span is not shared, stop search
				break;
			}
		}
	}
}

struct vp_span* b_try_merge(unsigned b, struct vp_span* left, struct vp_span* right)
{
	if (left->end != right->start)
        return NULL;

	cascade_bucket_ptrs(b, right, left);

	// test
	// left->last_sync = false;

    // merge 'right' into 'left'
    left->end = right->end;
	// disable (gc)
#ifdef WM_ZERO
    right->start = 0; right->end = 0;
#endif
	LIST_REMOVE(right, freelist);
    WM_FREE(right);

    return left;
}

static void add_for_reuse(vaddr_t va, size_t npages)
{
    // TODO: batch this operation? virtmem_alloc already merges spans

    // bucketing
#if (NUM_BUCKETS == 1)
	freelist_free(opt_freelist, (void*)va, npages);
#else
    unsigned bucket = ((va - SHADOW_BASE) / bucket_size); 

	ASSERT0(bucket < NUM_BUCKETS);

    vaddr_t start = va;
    vaddr_t end = PG_OFFSET(start, npages);

    /*
	try bucket b: if null -> the area is not covered -> move left
	if not null: iterate upwards to find its destination
	update the concerned sub spans bucket ptrs
	*/

	int b = bucket;
	bool found = false;

	// if list is completely empty
	struct vp_freelist *list = opt_freelist;
	if(LIST_EMPTY(&list->items) || opt_freelist->items.lh_first == NULL){
		//fprintf(stderr, "list is empty. new span (bucket %u)\n", b);
		// create new span
		struct vp_span *span = WM_ALLOC(sizeof(struct vp_span));
		span->start = start;
		span->end = end;
		span->last_sync = false;
		LIST_INSERT_HEAD(&list->items, span, freelist);
		// update bucket ptr
		// sub_spans[b] = span;

		// get end_bucket of 'end'
		unsigned end_bucket = ((end - SHADOW_BASE) / bucket_size); 
		for(; b <= end_bucket; b++){
			sub_spans[b] = span;
		}
		return;
	}

	// if dest. bucket is empty
	if(sub_spans[b] == NULL){
		//fprintf(stderr, "bucket %u is empty, find prev\n", b);
		// find the previous bucket with content s.t. we can insert
		if(b > 0){
			for(; b >= 0; b--){ // b = b-1?
				if(sub_spans[b] != NULL){
					found = true;
					break;
				}
			}
		}
		if(!found){
			// no previous -> span becomes the list head
			// insert before the current head		
			struct vp_span *head = list->items.lh_first;

			// can merge?
			if(end == head->start){
				//fprintf(stderr, "no prev found, can merge with head\n");
				head->start = start;
				head->last_sync = false;
				sub_spans[bucket] = head;
			}
			else{
				//fprintf(stderr, "no prev found, new head\n");
				struct vp_span *span = WM_ALLOC(sizeof(struct vp_span));
				span->start = start;
	        	span->end = end;
    		    span->last_sync = false;
				LIST_INSERT_BEFORE(head, span, freelist);
        		//sub_spans[bucket] = span;
				// get end_bucket of 'end'
        		unsigned end_bucket = ((end - SHADOW_BASE) / bucket_size); 
        		for(; bucket <= end_bucket; bucket++){ 
            		sub_spans[bucket] = span;
        		}
			}
			return;
		}

		//fprintf(stderr, "prev of empty bucket is bucket %u\n", b);
	}

	//fprintf(stderr, "using bucket %u for insertion (og %u)\n", b, bucket);

	// bucket 'b' should concern insertion
	// bucket 'bucket' still needs potential pointer update

	// cascading bucket pointer updates:
	// not needed for insert-before: they would not contain the other bucket
	// not needed for merge with prev: span ptr stays intact
	// is needed for merge with next: new span can join on the left side,
	// essentially freeing the next

	struct vp_span *prev=NULL, *next;
	for(next = sub_spans[b]; next != NULL; next = next->freelist.le_next){
		if(next->start >= end){
			break;
		}
		prev = next;
	}
	
	// try merge with prev
	if(prev != NULL && prev->end == start){
		prev->end = end;
		// test
		// prev->last_sync = false;
		if(next != NULL){ // next is not end
			b_try_merge(b, prev, next);
		}
		//fprintf(stderr, "merging with prev: %lx\n", prev->start);
			
		if(found){
			sub_spans[bucket] = prev;
			// bucket came from NULL, so nothing depends on it
		}
		return;
	}

	// try merge with next
	if(next != NULL && next->start == end){
		next->start = start;
		next->last_sync = false;
		if(prev != NULL){
			if(b_try_merge(b, prev, next) != NULL){
				if(found){ 
					sub_spans[bucket] = prev;
					return;
				}
			}
		}
		
		if(found){
			sub_spans[bucket] = next;
			// bucket came from NULL, so nothing depends on it
		}
		//fprintf(stderr, "merging with next: %lx\n", next->end);
		return;
	}	
	
	// could not merge in current bucket range
	struct vp_span *span = WM_ALLOC(sizeof(struct vp_span));
	if (UNLIKELY(!span)) {
        	LOG("could not allocate vp_span: out of memory?\n");
        	return;
   	}
	span->start = start;
	span->end = end;
	span->last_sync = false;

	if(found){
		// if the bucket ptr was empty, let it point to new span
		//sub_spans[bucket] = span;
		// get end_bucket of 'end'
        unsigned end_bucket = ((end - SHADOW_BASE) / bucket_size); 
        for(; bucket <= end_bucket; bucket++){ 
            sub_spans[bucket] = span;
        }
	}

	//fprintf(stderr, "could not merge. new span\n");

	if(prev){
        LIST_INSERT_AFTER(prev, span, freelist);
	} else if(next != NULL){ // next is not end of list (NULL)
        LIST_INSERT_BEFORE(next, span, freelist);
		if(next == sub_spans[bucket]){
			// we inserted before the bucket ptr. update.
			sub_spans[bucket] = span;
		}
		/*if(next == sub_spans[b]){
			// ?? is this even possible
			sub_spans[b] = span;
		}*/
	} 
#endif
    //LOG("we can add VA=%p to free list!\n", (void*)va);
}

static inline void sweep_curobj_done(void)
{
    size_t npages;
   // if(sweep_curobj_marked)
   //     LOG("Sweep obj %lx-%lx marked=%d\n", sweep_curobj_start, sweep_curobj_end, sweep_curobj_marked);
    if (sweep_curobj_end) {
        npages = (sweep_curobj_end - sweep_curobj_start) / PGSIZE;

        if (!sweep_curobj_marked)
            add_for_reuse(sweep_curobj_start, npages);
        else if (sweep_curobj_num_cleared) {
            /* Roll back the un-invalidation of PTEs. */
            rollback_invalidations(sweep_curobj_start, sweep_curobj_num_cleared, npages);
        }
    }
    sweep_curobj_reset();
}
static inline void sweep_curobj_add(vaddr_t va, size_t npages)
{
    if (sweep_curobj_end) {
	//fprintf(stderr, "va %lx end %lx start %lx\n", va, sweep_curobj_end, sweep_curobj_start);
        ASSERT0(va == sweep_curobj_end);
        sweep_curobj_end += npages * PGSIZE;
    } else {
        sweep_curobj_start = va;
        sweep_curobj_end = va + npages * PGSIZE;
    }
}

static bool sweep_pt_compressed_cpt(cpt_t *cpt, vaddr_t partial_va)
{
    /* We are always at level PT_L1.
     * We know entire thing is unmarked (otherwise mark_ptr would have
     * uncompressed this entry). */

    size_t num_free_entries = 0;
    size_t i;

    //fprintf(stderr, "Start Sweeping compressed cpt=%p va=%lx\n", cpt, partial_va);
    //LOG("Start Sweeping compressed cpt=%p va=%lx\n", cpt, partial_va);
    //dump_cpt(cpt, partial_va);

    for (i = 0; i < PT_NUM_ENTRIES; i++) {
	bool is_objend = cpt_get_entry(cpt, i, CPT_OBJEND);
	bool is_inval = cpt_get_entry(cpt, i, CPT_INVALIDATED);
	bool is_marked = 0; /* XXX For when we support compressed marking. */
	vaddr_t va = partial_va | (i * PGSIZE);
	
        //fprintf(stderr, " sweep cpt i=%zu va=%lx curend=%lx isend=%d isinval=%d\n", i, va, sweep_curobj_end, is_objend, is_inval);
        if (!is_inval) {
            num_free_entries++;
            continue;
        }

        sweep_curobj_add(va, 1);

        if (is_marked)
            sweep_curobj_marked = 1;
        else if (!sweep_curobj_marked) {
            //cpt_set_entry(cpt, i, CPT_OBJEND, 0);
            cpt_set_entry(cpt, i, CPT_INVALIDATED, 0);
            sweep_curobj_num_cleared++;
            num_free_entries++;
        }

        if (is_objend)
            sweep_curobj_done();
    }
    
    //dump_cpt(cpt, partial_va);
    return num_free_entries == PT_NUM_ENTRIES;
}

static bool sweep_pt_compressed_pte(enum pt_level level,
                                    pte_t *pte,
                                    vaddr_t partial_va)
{
    // XXX start/end idx support?
    ASSERT0(level == PT_L2);
    ASSERT0(pte_is_compressed(*pte, level));

    if (*pte & PTE_CMS_ONEBIG) {
        //LOG("+++++ CMS BIGONE %lx pte=%lx\n", partial_va, *pte);
        sweep_curobj_add(partial_va, PT_NUM_ENTRIES);
        if (*pte & PTE_MARKED)
            sweep_curobj_marked = 1;
        else if (!sweep_curobj_marked) {
            /* Optimistically mark reusable (leave ONEBIG bit for rollback). */
            *pte &= ~PTE_COMPRESSED;
            sweep_curobj_num_cleared += PT_NUM_ENTRIES;
            return true;
        }

        return false;

    } else if (*pte & PTE_CMS_ALLSMALL) {
        /* While this cpt has all OBJEND bits set, the first page in this cpt
         * may belong to an object that was started earlier, and it may be
         * marked. If it is marked we have to uncompress, because the rest of
         * the pages/objects in this cpt are invalid and unmarked (and thus will
         * become reusable) resulting in a mixed valid/invalid cpt. */

        //LOG("+++++ CMS ALLSMALL %lx pte=%lx marked=%d\n", partial_va, *pte, sweep_curobj_marked);

        if (sweep_curobj_marked) {
            /* TODO: uncompress to a cpt instead of full pt */
            pte_t *nextpt;
            uncompress_pte(level, pte);
            nextpt = (pte_t*)pt_paddr2vaddr(*pte & PTE_FRAME);
            sweep_pt_rec(level - 1, nextpt, 0, PT_NUM_ENTRIES, partial_va);

            return false;
        } else {
            /* Batch all individual (unmarked) objects. There'd never be
             * a situation where we'd have to roll back. */
            *pte = PTE_EMPTY;
            sweep_curobj_add(partial_va, PT_NUM_ENTRIES);
            sweep_curobj_done();

            return true;
        }
    } else {
        cpt_t *cpt = (cpt_t *)((*pte & PTE_FRAME_CPT) + PAGE_OFFSET);
	//LOG("pte=%p *pte=%lx, cpt=%p cptt=%lu\n", pte, *pte, cpt, *pte & PTE_FRAME);
        bool can_free = sweep_pt_compressed_cpt(cpt, partial_va);
        if (can_free) {
            cpt_free(cpt);
            *pte = PTE_EMPTY;
        }
        return can_free;
    }
}

static bool sweep_pt_rec(enum pt_level level, pte_t *pt,
                         size_t idx_start, size_t idx_end, vaddr_t partial_va)
{
    size_t num_free_entries = 0;
    size_t i;

    for (i = idx_start; i < idx_end; i++) {
        bool is_compressed;
        vaddr_t va;

        is_compressed = pte_is_compressed(pt[i], level);
        va = partial_va | (i << pt_level_shift(level));
        if (level == PT_L4)
            va = sext(va);

	// fcg: TODO: not sure
	// va vs highest_shadow
	//if(va >= highest_shadow){
	//    num_free_entries += idx_end - i;
	//    break;
	//}

        if (level > PT_L1 && (pt[i] & PTE_P) && (pt[i] & PTE_ALIASSES)) {
            pte_t *nextpt = (pte_t*)pt_paddr2vaddr(pt[i] & PTE_FRAME);
            bool can_free = sweep_pt_rec(level - 1, nextpt, 0, PT_NUM_ENTRIES,
                                         va);

            if (can_free) {
                // pp_free_one(pt[i] & PTE_FRAME);
                //LOG("freed a page on level %d\n", level);
#ifdef __TRACK_MEM_USAGE
	        curr_pt_count--;
#endif
		free_pages((unsigned long)phys_to_virt(pt[i] & PTE_FRAME), 0);
                pt[i] = PTE_EMPTY;
                num_free_entries++;
		}
        } else if (is_compressed) {
            //LOG("compressed = TRUE at level %d\n", level);
	    //LOG("i=%lu pt=%p &pt=%p\n", i, pt, &pt);
            bool freed = sweep_pt_compressed_pte(level, &pt[i], va);
            if (freed)
                num_free_entries++;
        } else if ((pt[i] & PTE_INVALIDATED)) {
            bool is_obj_end;

            if (level > PT_L1) {
                // LOG("Found invalidated pt at l%d: %lx\n", level, pt[i]);
                //dumpsome();
            }
            ASSERT0(level == PT_L1);

            sweep_curobj_add(va, pt_num_mapped_pages(level));
            is_obj_end = !!(pt[i] & PTE_OBJEND);

            if ((pt[i] & PTE_MARKED))
                sweep_curobj_marked = 1;
            else if (!sweep_curobj_marked) {
                /* Optimistically clear invalidated status */
                pt[i] = PTE_EMPTY;
                sweep_curobj_num_cleared++;
                num_free_entries++;
            }

            if (is_obj_end)
                sweep_curobj_done();
        } else if (!(pt[i] & PTE_P)) {
            num_free_entries++;
        }

        if (pt[i] & PTE_MARKED && (!is_compressed || (is_compressed && pt[i] & PTE_CMS_ONEBIG)))
            pt[i] &= ~PTE_MARKED;
    }
    return num_free_entries == PT_NUM_ENTRIES;
}

void build_sub_spans(void)
{	
	/*
	loop through the freelist
	whenever there is a start addr that is bigger than
	the chunk start, point the bucket there
	if the end addr is larger than the next chunk, alias it too
	*/

	// empty freelist
	if(opt_freelist == NULL || opt_freelist->items.lh_first == NULL){
		return;
	}

	unsigned b = 0;
	uint64_t bucket_offset = SHADOW_BASE;
	uint64_t bucket_next = SHADOW_BASE+bucket_size;
	struct vp_span *span;
	LIST_FOREACH(span, &opt_freelist->items, freelist){
		// also check the mega span?
		if((span->start < bucket_offset && span->end > bucket_offset)
		|| (span->start >= bucket_offset && span->start < bucket_next)){
		//if(span->start >= bucket_offset && !(span->end > highest_shadow)){
			do{
				//fprintf(stderr, "b=%u (off: %lx): %lx ~ %lx\n", b, bucket_offset, span->start, span->end);
				sub_spans[b] = span;
				//bucket_offset += bucket_size;
				bucket_offset = bucket_next;
				bucket_next += bucket_size;
				b++;
			} while(span->end >= bucket_offset && b < NUM_BUCKETS);
		}
		
		if(b==NUM_BUCKETS-1 || b==NUM_BUCKETS) break;
	}
}

void gc_run(void)
{
    // fprintf(stderr, "[Running Garbage Collector!]\n");
    // MARK
    mark_regs();   
    dangzero_mark_heap(&mark_ptr); // kmod: datasegs, stack, heap, libs


#if (NUM_BUCKETS > 1)
	uint64_t shadow_size = highest_shadow - SHADOW_BASE;
	bucket_size = (shadow_size / NUM_BUCKETS) + 0x1000; // round

	sub_spans = WM_ALLOC(sizeof(struct vp_span*) * NUM_BUCKETS);
	memset(sub_spans, 0, sizeof(struct vp_span*) * NUM_BUCKETS);
	build_sub_spans();
#endif

	//fprintf(stderr, "g_freelist=%p\n", g_freelist);
	//fprintf(stderr, "highest_shadow=%lx\n", highest_shadow);
	//fprintf(stderr, "shadow_size=%lx\n", shadow_size);
	//fprintf(stderr, "bucket_size=%lu\n", bucket_size);
	//fflush(stderr);

#ifdef __TRACK_SHADOW_SIZE
    output_shadow_size(false);
#endif

    // SWEEP
    sweep_all();

#ifdef __TRACK_SHADOW_SIZE 
    output_shadow_size(true);
#endif

#if (NUM_BUCKETS > 1)
	WM_FREE(sub_spans);
#endif
}

void gc_init(void)
{
    uintptr_t stack_bottom;
    uintptr_t stack_ptr = get_stack_pointer();
    uintptr_t bss_ptr = (uintptr_t)&bss_seg_var;
    uintptr_t data_ptr = (uintptr_t)&data_seg_var;

    // printf("gc_init: %lx %lx %lx\n", stack_ptr, bss_ptr, data_ptr);

    dangzero_find_vma_bounds(stack_ptr, &stack_bottom, &stack_top);
    dangzero_find_vma_bounds(bss_ptr, &bss_start, &bss_end);
    dangzero_find_vma_bounds(data_ptr, &data_start, &data_end);

    // printf("stack: %lx ~ %lx\n", stack_bottom, stack_top);
    // printf("bss: %lx ~ %lx\n", bss_start, bss_end);
    // printf("data: %lx ~ %lx\n", data_start, data_end);
}
#endif
