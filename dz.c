#define _GNU_SOURCE // for non-POSIX RTLD_NEXT
#include <dlfcn.h> // dlsym
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h> // malloc_usable_size
#include <sys/types.h> // pid_t
#include <unistd.h> // sleep
#include <stdlib.h> // strtoul
#include <pthread.h>
#include <sys/mman.h>
#include <time.h>
#include <sched.h>
#include <limits.h>
#include <stdbool.h>
//#include <signal.h>
//#include <assert.h>

#include "queue.h"
#include "dz.h"
#include "gc.h"


//#define __SPEC_MODE
//#define __NGINX_MODE
//#define __JULIET_MODE
#define __CVE_MODE

#ifdef __CVE_MODE
#include <signal.h>
#endif

#ifdef __TRACK_MEM_USAGE
#include <sys/resource.h>
uint64_t max_pt_count = 0;
uint64_t curr_pt_count = 0;
#endif

//gcc -fPIC -shared -pthread -O2 -o wrap.so dz.c gc.c -ldl

static uint8_t process = 0;
uintptr_t* g_cr3 = NULL;

#define _last_pdpt      last_pdpt
#define _last_pde       last_pde
#define _last_pte       last_pte
#define _last_pml4_index        last_pml4_index
#define _last_pdpt_index        last_pdpt_index
#define _last_pde_index         last_pde_index
#define _last_pte_index         last_pte_index

struct span {
        uintptr_t start;
        uintptr_t end;
};
// initial main span
static struct span free_span;

// page walk optimization
uintptr_t *last_pdpt, *last_pde, *last_pte;
unsigned short last_pml4_index = PML4_SHADOW_START;
unsigned short last_pdpt_index = 0;
unsigned short last_pde_index = 0;
unsigned short last_pte_index = USHRT_MAX; // overflow into 0

typedef int (*proto_posix_memalign)(void **memptr, size_t alignment, size_t size);
proto_posix_memalign __posix_memalign;

struct map_pa_va {
	uintptr_t pa;
	uintptr_t va;
};

struct _fork_sync {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int copy_done;
};

struct _fork_sync* fork_sync;
pthread_mutexattr_t fork_mutex_attr;
pthread_condattr_t fork_cond_attr;

proto_get_zeroed_page get_zeroed_page = (proto_get_zeroed_page) SYMBOL_ADDR_get_zeroed_page;
proto_free_pages free_pages = (proto_free_pages) SYMBOL_ADDR_free_pages;
proto___get_free_pages __get_free_pages = (proto___get_free_pages) SYMBOL_ADDR___get_free_pages;
proto_kfree kfree = (proto_kfree) SYMBOL_ADDR_kfree;
proto_kmalloc kmalloc = (proto_kmalloc) SYMBOL_ADDR_kmalloc;
proto_kallsyms_lookup_name kallsyms_lookup_name = (proto_kallsyms_lookup_name) SYMBOL_ADDR_kallsyms_lookup_name;

#ifdef __GC
// fork + destructor: highest_shadow
#ifdef __GC_WATERMARK
uint64_t invalidated_pages = 0;
#endif
uint64_t highest_shadow = 0;
bool fragmented = false;
struct vp_span* cur_span = NULL;

// free list stuff
static inline size_t span_num_pages(struct vp_span *span)
{    
	return (span->end - span->start) / PGSIZE;
}

static inline bool span_empty(struct vp_span *span)
{
    return span->start == span->end;
}

#define VP_FREELIST_INIT(PTR) { \
    .items = LIST_HEAD_INITIALIZER(&(PTR)->items), \
}

// bucketing
//struct vp_freelist* g_freelist = NULL;
uint64_t bucket_size = 0;
//unsigned curr_bucket = 0;

// new freelist management
struct vp_freelist* opt_freelist = NULL; //VP_FREELIST_INIT(&opt_freelist);
struct vp_span** sub_spans = NULL;

static uint64_t shadow_pages_in_use()
{
	uint64_t total = 0;
	struct vp_span *span;

	if(opt_freelist != NULL && opt_freelist->items.lh_first != NULL){
		LIST_FOREACH(span, &(opt_freelist->items), freelist){
	        total += span_num_pages(span);
    	}
	}

	uint64_t base = ((uint64_t)SHADOW_END-SHADOW_BASE) / PAGE_SIZE; // num pages
	
	return base - total;
}

static void update_span_last_ptrs(struct vp_span* span)
{
	// page walk the span->start for last_ptrs
	uint64_t start = span->start;
	last_pml4_index = PML4_INDEX(start);
	last_pdpt = step_shadow_table(g_cr3, last_pml4_index);
	last_pdpt_index = PDPT_INDEX(start);
	last_pde = step_shadow_table(last_pdpt, last_pdpt_index);
	last_pde_index = PDE_INDEX(start);
#ifdef __GC_PT_COMPRESS
	last_pte = step_shadow_table_L2cpt(last_pde, last_pde_index);
#else
	last_pte = step_shadow_table(last_pde, last_pde_index);
#endif
	last_pte_index = (unsigned short)(PTE_INDEX(start)-1); // alloc does ++
	span->last_sync = true;
}

struct vp_span *try_merge_spans(struct vp_span *left, struct vp_span *right)
{
    if (left->end != right->start)
        return NULL;

    LOG("merging span %p (%p - %p) with span %p (%p - %p)\n",
        left, (void *)left->start, (void *)left->end,
        right, (void *)right->start, (void *)right->end);

    // merge 'right' into 'left'
    left->end = right->end;
    LIST_REMOVE(right, freelist);
    
    // fcg: removed spans need to get zeroed out to not cause GC marking
    // alternatively, we can use kmalloc+kfree, but may be slower
#ifdef WM_ZERO
    right->start = 0; right->end = 0;
#endif
    WM_FREE(right);

    return left;
}

int freelist_free(struct vp_freelist *list, void *p, size_t npages)
{
    // ASSERT0((vaddr_t)p % PGSIZE == 0);
    // ASSERT0(npages > 0);

    vaddr_t start = (vaddr_t)p;
    vaddr_t end = PG_OFFSET(start, npages);

    // find the two spans between which the new span would go
    struct vp_span *prev_span = NULL, *next_span;
    LIST_FOREACH(next_span, &list->items, freelist) {
        if (next_span->start >= end)
            break;

        prev_span = next_span;
    }

    // try merging with prev_span
    if (prev_span != NULL && prev_span->end == start) {
        // LOG("merging freed range %p - %p into prev span %p (%p - %p)\n",
            // (void *)start, (void *)end, prev_span, (void *)prev_span->start,
            // (void *)prev_span->end);

        prev_span->end = end;

        // try merging prev_span with next_span
        if (next_span != LIST_END(&list->items))
            try_merge_spans(prev_span, next_span);

        return 0;
    }

    // try merging with next_span
    if (next_span != LIST_END(&list->items) && next_span->start == end) {
        LOG("merging freed range %p - %p into next span %p (%p - %p)\n",
            (void *)start, (void *)end, next_span, (void *)next_span->start,
            (void *)next_span->end);

        next_span->start = start;
	// lazy assign last_ptrs
	next_span->last_sync = false;

        // try merging prev_span with next_span
        if (prev_span)
            try_merge_spans(prev_span, next_span);

        return 0;
    }

    // failed to merge into existing spans, so we'll have to create a new span
    struct vp_span *span = WM_ALLOC(sizeof(struct vp_span));
    if (UNLIKELY(!span)) {
        LOG("could not allocate vp_span: out of memory?\n");
        return -1;
    }

    span->start = start;
    span->end = end;
    // lazy assign last_ptrs
    span->last_sync = false;

    LOG("new span %p: %p - %p (%zu pages)\n", span, (void *)span->start, (void *)span->end, span_num_pages(span));

    // insert the new span
    if (prev_span) {
        LIST_INSERT_AFTER(prev_span, span, freelist);
    } else if (next_span != LIST_END(&list->items)) {
        LIST_INSERT_BEFORE(next_span, span, freelist);
    } else {
        LIST_INSERT_HEAD(&list->items, span, freelist);
    }

    return 0;
}

static void freelist_reset(struct vp_freelist *list)
{
    struct vp_span *span, *tmp;
    LIST_FOREACH_SAFE(span, &list->items, freelist, tmp) {
        LIST_REMOVE(span, freelist);
#ifdef WM_ZERO
        span->start = 0; span->end = 0;
#endif
	WM_FREE(span);
    }
}
#endif // GC

static uint64_t shadow_page_size()
{
        // size of the shadow space, i.e.,
        // how much is currently unavailable for re-use
        uint64_t size = 0;
#ifdef __GC
        if(highest_shadow != 0){
                // freelist_size is in number of pages
                //size = ((highest_shadow - SHADOW_BASE) / PAGE_SIZE) - freelist_size();
			size = shadow_pages_in_use();
	}
#else
	size = ((free_span.start - SHADOW_BASE) / PAGE_SIZE);
#endif                
        return size;
}

#ifdef __TRACK_SHADOW_SIZE
FILE* shw_fp = NULL;
uint64_t nallocs = 0;
unsigned out_cnt = 0;

void output_shadow_size(bool gc) 
{
        process=0;
        if(shw_fp == NULL){
		pid_t pid = getpid();
		char piddy[6];
		sprintf(piddy, "%d", pid);

		char path[256];
		strcpy(path, "/home/u16/Documents/shadowlog_");
		strcat(path, piddy);

                shw_fp = fopen(path, "w");
                if(shw_fp == NULL){
                process=1; 
                return;
                }
	}
        uint64_t shadow_sz = shadow_page_size();
	// __TRACK_MEM_USAGE
	uint64_t total_rss_pages = 0;
	
	long rss = 0L;
        FILE* fp = NULL;
        if ( (fp = fopen( "/proc/self/statm", "r" )) == NULL ){
	    process=1;
            return; /* Can't open? */
        }
        if ( fscanf( fp, "%*s%ld", &rss ) != 1 )
        {
            fclose( fp );
	    process=1;
            return;      /* Can't read? */
        }
        fclose( fp );
        total_rss_pages = (size_t)rss;
	//total_rss_pages += curr_pt_count;

        if(gc){
#ifdef __NGINX_MODE
		//pid_t pid = getpid();
        	fprintf(shw_fp, "%u %lu %lu -- %lu %lu (gc)\n", out_cnt, nallocs, shadow_sz, total_rss_pages, curr_pt_count);
#else
        	fprintf(shw_fp, "%u %lu %lu (gc)\n", out_cnt, nallocs, shadow_sz);
#endif
		//fprintf(shw_fp, "cpt list size %lu (gc)\n", out_cpt_list_size());
        }
        else{
#ifdef __NGINX_MODE
		//pid_t pid = getpid();
                fprintf(shw_fp, "%u %lu %lu -- %lu %lu\n", out_cnt, nallocs, shadow_sz, total_rss_pages, curr_pt_count);
#else
                fprintf(shw_fp, "%u %lu %lu\n", out_cnt, nallocs, shadow_sz);
#endif
		//fprintf(shw_fp, "cpt list size %lu\n", out_cpt_list_size());
        }

	out_cnt++;
        process=1;
}
#endif

// ---------------------- //

uintptr_t* create_page_table(uintptr_t* table, unsigned short entry)
{
	// get a kernel memory page for the new table
	// uintptr_t kpage = get_zeroed_page(GFP_NOWAIT); // GFP_NOWAIT

	uintptr_t kpage = __get_free_pages(GFP_NOWAIT, 0);
	memset((void*)kpage, 0, PAGE_SIZE);

#ifdef __TRACK_MEM_USAGE
	curr_pt_count++;
	if(curr_pt_count > max_pt_count){
		max_pt_count = curr_pt_count;
	}
#endif

	// connect the previous table with the next table
#ifdef __GC
	*(table + entry) = virt_to_phys((void*)kpage) | PAGE_PRESENT | PAGE_WRITABLE | PTE_ALIASSES;
#else
	*(table + entry) = virt_to_phys((void*)kpage) | PAGE_PRESENT | PAGE_WRITABLE;
#endif
	// new page in new address space, no flush TLB

	// return virt addr of table
	return (uintptr_t*)kpage;
}

static uintptr_t* get_table_page(uintptr_t* table, unsigned short index)
{
	uintptr_t page = *(table+index);
	if(!(page & PAGE_PRESENT))
		return NULL;

	// PAGE_FRAME to remove flag bits
	// PAGE_OFFSET to return kernel-space virtual address
	// note: make sure this cast wraps the entire result (lol)
	return (uintptr_t*)((page & PAGE_FRAME) + PAGE_OFFSET);
}

static uintptr_t* get_table_page_L2cpt(uintptr_t* table, unsigned short index, bool *cpt)
{
	// this assumes table == L2 (PD)
	uintptr_t page = *(table+index);
	if(page & PAGE_PRESENT){
		*cpt = false;
		return (uintptr_t*)((page & PAGE_FRAME) + PAGE_OFFSET);
	}
	else if(page & PTE_COMPRESSED){
		if(!(page & PTE_CMS_ONEBIG) && !(page & PTE_CMS_ALLSMALL)){
			*cpt = true;
			return (uintptr_t*)((page & PTE_FRAME_CPT) + PAGE_OFFSET);
		}
	}
	
	*cpt = false;
	return NULL;
}

static uintptr_t* get_table_page_nocheck(uintptr_t* table, unsigned short index)
{
	// here we assume the page is present... (nocheck)
	return (uintptr_t*)((*(table+index) & PAGE_FRAME) + PAGE_OFFSET);
}

phys_addr_t get_phys_addr_user(uintptr_t addr)
{
	uintptr_t* page = g_cr3;
	phys_addr_t phys_page;
	unsigned short index;

	// level 4
	index = PML4_INDEX(addr);
	page = get_table_page(page, index);
	if(UNLIKELY(page == NULL)) return 0;

	// level 3
	index = PDPT_INDEX(addr);
	page = get_table_page(page, index);
	if(UNLIKELY(page == NULL)) return 0;

	// level 2
	index = PDE_INDEX(addr);
	page = get_table_page(page, index);
	if(UNLIKELY(page == NULL)) return 0;

	// phys page
	index = PTE_INDEX(addr);
	phys_page = *(page+index);
	if(UNLIKELY(!(phys_page & PAGE_PRESENT))) return 0;

	return phys_page;
}

uintptr_t* step_shadow_table_L2cpt(uintptr_t* table, unsigned short index)
{
	// this assumes table == L2 (PD)
	uintptr_t* next_table;
	if(*(table+index) & PAGE_PRESENT){
		next_table = get_table_page_nocheck(table, index);
	}
	else if(*(table+index) & PTE_COMPRESSED){
		next_table = uncompress_pte(2, (pte_t*)(table+index));
	}
	else{
		// create new level
		next_table = create_page_table(table, index);
	}

	return next_table;
}

uintptr_t* step_shadow_table(uintptr_t* table, unsigned short index)
{
	uintptr_t* next_table;
	if(!(*(table+index) & PAGE_PRESENT)){
		next_table = create_page_table(table, index);
	}
	else{
		next_table = get_table_page_nocheck(table, index);
	}
	return next_table;
}


int can_reclaim_pt(uintptr_t* pt)
{
	unsigned short index;
	for(index = 0; index < 512; index++){
		if(!(*(pt+index) & PTE_INVALIDATED)){
			return 0;
		}
	}
	return 1;
}


void disable_shadow_one(uintptr_t addr)
{
	// uintptr_t* page;
	uintptr_t *pdpt, *pde, *pte;
	unsigned short pml4_index, pdpt_index, pde_index, pte_index;

	// do a page walk to find PTE of addr

	// level 4
	pml4_index = PML4_INDEX(addr);
	pdpt = get_table_page(g_cr3, pml4_index); //pdpt=cr3+pml4_index
	if(UNLIKELY(pdpt == NULL)) return;

	// level 3
	pdpt_index = PDPT_INDEX(addr);
	pde = get_table_page(pdpt, pdpt_index); //pde=pdpt+pdpt_index
	if(UNLIKELY(pde == NULL)) return;

	// level 2
	pde_index = PDE_INDEX(addr);
	pte = get_table_page(pde, pde_index); //pte=pde+pde_index
	if(UNLIKELY(pte == NULL)) return;

	// level 1
	pte_index = PTE_INDEX(addr);

	// remove PAGE_PRESENT from the PTE
	*(pte+pte_index) = PTE_INVALIDATED;
#ifdef __GC
	*(pte+pte_index) |= PTE_OBJEND;
#endif
	
	//*(pte+index) &= ~(PAGE_PRESENT); // *pte+pte_index == pointer to PA

	// flush TLB
	asm volatile("invlpg (%0)" :: "r" (addr) : "memory");

	//try_collect_pt(addr, 1);

#if defined(__GC) && defined(__GC_PT_COMPRESS)
	try_compress_pt(addr, 1);
#elif defined(__PT_RECLAIM)
	// PT RECLAIM
	if(can_reclaim_pt(pte)){
		*(pde+pde_index) = PTE_INVALIDATED | PTE_ALIASSES;
		free_pages((unsigned long)pte, 0);
#ifdef __TRACK_MEM_USAGE
		curr_pt_count--;
#endif
		if(can_reclaim_pt(pde)){
			*(pdpt+pdpt_index) = PTE_INVALIDATED | PTE_ALIASSES;
			free_pages((unsigned long)pde, 0);
#ifdef __TRACK_MEM_USAGE
              		curr_pt_count--;
#endif
		}
	}
#endif

#ifdef __GC_WATERMARK
	invalidated_pages++;
#endif

}

void disable_shadows(uintptr_t base, size_t num_pages)
{
	uintptr_t *pdpt, *pde, *pte;
	unsigned short pml4_index, pdpt_index, pde_index, pte_index;
#ifdef __GC
	uintptr_t saveaddr = base;
#endif

	// page walk the first shadow
	// level 4
	pml4_index = PML4_INDEX(base);
	pdpt = get_table_page(g_cr3, pml4_index);
	if(UNLIKELY(pdpt == NULL)) return;

	// level 3
	pdpt_index = PDPT_INDEX(base);
	pde = get_table_page(pdpt, pdpt_index);
	if(UNLIKELY(pde == NULL)) return;

	// level 2
	pde_index = PDE_INDEX(base);
	pte = get_table_page(pde, pde_index);
	if(UNLIKELY(pte == NULL)) return;

	// level 1
	pte_index = PTE_INDEX(base);

	// remove PAGE_PRESENT from the PTE
	*(pte+pte_index) = PTE_INVALIDATED;
	//*(pte+pte_index) &= ~(PAGE_PRESENT);

	// flush TLB
	asm volatile("invlpg (%0)" :: "r" (base) : "memory");

	// subsequent shadow pages are contiguous
	// if get_table_page fails (returns NULL) we need to cancel
	// this can only happen if something else disabled the shadow...

	size_t p;
	for(p = 1; p < num_pages; p++){
		// move to next page table entry
		if(pte_index == MAX_PAGE_INDEX){
			pte_index = 0;
			if(pde_index == MAX_PAGE_INDEX){
				pde_index = 0;
				if(pdpt_index == MAX_PAGE_INDEX){
					pdpt_index = 0;
					//if(pml4_index == PML4_SHADOW_END) // not on free
					pml4_index++;
					// update subsequent level pages (pdpt, pde, pte)
					pdpt = get_table_page(g_cr3, pml4_index);
					pde = get_table_page(pdpt, 0);
					pte = get_table_page(pde, 0);
				}
				else{
#ifdef __PT_RECLAIM
					// pte can already be reclaimed at this point
					if(can_reclaim_pt(pde)){
						*(pdpt+pdpt_index) = PTE_INVALIDATED | PTE_ALIASSES;
						free_pages((unsigned long)pde, 0);
#ifdef __TRACK_MEM_USAGE
              					curr_pt_count--;
#endif
					}
#endif
					pdpt_index++;
					// update subsequent level pages (pde, pte)
					pde = get_table_page(pdpt, pdpt_index);
					pte = get_table_page(pde, 0);
				}
			}
			else{
#ifdef __PT_RECLAIM
				if(can_reclaim_pt(pte)){
					*(pde+pde_index) = PTE_INVALIDATED | PTE_ALIASSES;
					free_pages((unsigned long)pte, 0);
#ifdef __TRACK_MEM_USAGE
              				curr_pt_count--;
#endif
				}
#endif
				pde_index++;
				// update subsequent level pages (pte)
				pte = get_table_page(pde, pde_index);
			}
		}
		else{
			pte_index++;
		}

		// remove PAGE_PRESENT from the PTE
		*(pte+pte_index) = PTE_INVALIDATED;
		//*(pte+pte_index) &= ~(PAGE_PRESENT);
#ifdef __GC
		if(p+1 == num_pages){
			*(pte+pte_index) |= PTE_OBJEND;
		}
#endif
		// flush TLB
		base += PAGE_SIZE;
		asm volatile("invlpg (%0)" :: "r" (base) : "memory");
	}

	//try_collect_pt(saveaddr, num_pages);
#if defined(__GC) && defined(__GC_PT_COMPRESS)
	try_compress_pt(saveaddr, num_pages);
#elif defined(__PT_RECLAIM)
	// PT RECLAIM
	if(can_reclaim_pt(pte)){
		*(pde+pde_index) = PTE_INVALIDATED | PTE_ALIASSES;
		free_pages((unsigned long)pte, 0);
#ifdef __TRACK_MEM_USAGE
    	curr_pt_count--;
#endif
		if(can_reclaim_pt(pde)){
			*(pdpt+pdpt_index) = PTE_INVALIDATED | PTE_ALIASSES;
			free_pages((unsigned long)pde, 0);
#ifdef __TRACK_MEM_USAGE
		              		curr_pt_count--;
#endif
		}
	}
#endif

#ifdef __GC_WATERMARK
        invalidated_pages += num_pages;
#endif
}

uintptr_t* create_shadow_one(uintptr_t canon, size_t offset)
{
	phys_addr_t phys_user;
	volatile int8_t tmp; // in case ptr is 1 byte?
	uintptr_t cur_shadow;

#ifdef __GC
	struct vp_span *span;
	if(cur_span != NULL){
		// any non-empty span is sufficient for 1 page
		span = cur_span;
	}
	else{
		span = opt_freelist->items.lh_first;
		
		// if span == NULL we are completely OOM
		// assert(span != NULL);		

		// update global cur_span
		if(cur_span != NULL){
			// disable prev span sync
			cur_span->last_sync = false;
		}
		cur_span = span;    					
	}
	
	if(!span->last_sync){
		update_span_last_ptrs(span);
		// TODO: skip initial entry++
	}

	cur_shadow = span->start;
	span->start += PAGE_SIZE;
	if(span->start > highest_shadow)
    	highest_shadow = span->start;		

	if (span_empty(span)) {
		LOG("span %p is now empty, deallocating\n", span);
        LIST_REMOVE(span, freelist);
#ifdef WM_ZERO
		span->start = 0; span->end = 0;
#endif
        WM_FREE(span);
		// set global span to NULL
		cur_span = NULL;
	}
#else
	cur_shadow = free_span.start;
	free_span.start += PAGE_SIZE;
#endif

	// get next shadow entry
	if(_last_pte_index == MAX_PAGE_INDEX){
		_last_pte_index = 0;
		if(_last_pde_index == MAX_PAGE_INDEX){
			_last_pde_index = 0;
			if(_last_pdpt_index == MAX_PAGE_INDEX){
				_last_pdpt_index = 0;
				// if last_pml4_index == PML4_SHADOW_END -> PANIC

				_last_pml4_index++;
				// update subsequent level pages (pdpt, pde, pte)
				_last_pdpt = step_shadow_table(g_cr3, _last_pml4_index);
				_last_pde = step_shadow_table(_last_pdpt, 0);
#ifdef __GC_PT_COMPRESS
				_last_pte = step_shadow_table_L2cpt(_last_pde, 0);
#else
				_last_pte = step_shadow_table(_last_pde, 0);
#endif
			}
			else{
				_last_pdpt_index++;
				// update subsequent level pages (pde, pte)
				_last_pde = step_shadow_table(_last_pdpt, _last_pdpt_index);
#ifdef __GC_PT_COMPRESS
				_last_pte = step_shadow_table_L2cpt(_last_pde, 0);
#else
				_last_pte = step_shadow_table(_last_pde, 0);
#endif
			}
		}
		else{
			_last_pde_index++;
			// update subsequent level pages (pte)
#ifdef __GC_PT_COMPRESS
			_last_pte = step_shadow_table_L2cpt(_last_pde, _last_pde_index);
#else
			_last_pte = step_shadow_table(_last_pde, _last_pde_index);
#endif
		}
	}
	else{
		_last_pte_index++;
	}

    // pre fault the page
    tmp = *(int8_t*)(canon);
    *(int8_t*)(canon) = tmp;

    // get the physical page belonging to the allocation
    phys_user = get_phys_addr_user(canon);

    // pte+pte_index now has to alias-point to the phys addr
    *(_last_pte+_last_pte_index) = (phys_user & PAGE_FRAME) | PAGE_PRESENT | PAGE_WRITABLE;

	// store the canonical page in malloc header at the start of the allocation
	*((uintptr_t*)(cur_shadow+offset)) = canon;

#ifdef __GC_WATERMARK
        if(invalidated_pages >= __GC_WATERMARK){
                invalidated_pages = 0;
                if(cur_span != NULL){
                        cur_span->last_sync = false;
                        cur_span = NULL;
                }
                gc_run();
        }
#endif

	// return the shadow page with the original in-page offset and canon padding
	return (uintptr_t*) (cur_shadow + offset + sizeof(void*));
}

uintptr_t* create_shadows(uintptr_t canon, size_t num_pages, size_t offset)
{
	uintptr_t start_shadow;
	phys_addr_t phys_user;
	volatile uintptr_t canon_page = canon;
	int8_t tmp;

#ifdef __GC
	struct vp_span *span;
	if(cur_span != NULL && span_num_pages(cur_span) >= num_pages){
		span = cur_span;
	}
	else{
		struct vp_freelist *list = opt_freelist;
		LIST_FOREACH(span, &list->items, freelist) {
			if (span_num_pages(span) >= num_pages) {
            	break;
        	}
		}
		
		// if span==NULL we are completely OOM
		// assert(span != NULL);

		if(cur_span != NULL){
	    	// disable prev span sync
        	cur_span->last_sync = false;
        }
        cur_span = span;
	}
		
	if(!span->last_sync){
    	update_span_last_ptrs(span);
		// TODO: skip initial entry++
	}

	start_shadow = span->start;
    span->start += num_pages * PGSIZE;
	if(span->start > highest_shadow)
    	highest_shadow = span->start;		

	// LOG("satisfying %zu page alloc from span %p => 0x%lx\n", num_pages, span, start_shadow);

	if (span_empty(span)) {
    	LOG("span %p is now empty, deallocating\n", span);
	    LIST_REMOVE(span, freelist);
#ifdef WM_ZERO
		span->start = 0; span->end = 0;
#endif
        WM_FREE(span);
		cur_span = NULL;
	}
#else
	start_shadow = free_span.start;
	free_span.start += (num_pages * PAGE_SIZE);
#endif

	size_t p;
	for(p = 0; p < num_pages; p++){

		// move to next page table entry
		if(_last_pte_index == MAX_PAGE_INDEX){
			_last_pte_index = 0;
			if(_last_pde_index == MAX_PAGE_INDEX){
				_last_pde_index = 0;
				if(_last_pdpt_index == MAX_PAGE_INDEX){
					_last_pdpt_index = 0;
					// if last_pml4_index == PML4_SHADOW_END -> PANIC

					_last_pml4_index++;
					// update subsequent level pages (pdpt, pde, pte)
					_last_pdpt = step_shadow_table(g_cr3, _last_pml4_index);
					_last_pde = step_shadow_table(_last_pdpt, 0);
#ifdef __GC_PT_COMPRESS
					_last_pte = step_shadow_table_L2cpt(_last_pde, 0);
#else
					_last_pte = step_shadow_table(_last_pde, 0);
#endif
				}
				else{
					_last_pdpt_index++;
					// update subsequent level pages (pde, pte)
					_last_pde = step_shadow_table(_last_pdpt, _last_pdpt_index);
#ifdef __GC_PT_COMPRESS
					_last_pte = step_shadow_table_L2cpt(_last_pde, 0);
#else
					_last_pte = step_shadow_table(_last_pde, 0);
#endif
				}
			}
			else{
				_last_pde_index++;
				// update subsequent level pages (pte)
#ifdef __GC_PT_COMPRESS
				_last_pte = step_shadow_table_L2cpt(_last_pde, _last_pde_index);
#else
				_last_pte = step_shadow_table(_last_pde, _last_pde_index);
#endif
			}
		}
		else{
			_last_pte_index++;
		}

		// pre fault page
        tmp = *(int8_t*)(canon_page);
        *(int8_t*)(canon_page) = tmp;

        // get phys addr of the page
        phys_user = get_phys_addr_user(canon_page);

        // move canon page to the next one
        canon_page += PAGE_SIZE;

        // pte+pte_index now has to alias-point to the phys addr
        *(_last_pte+_last_pte_index) = (phys_user & PAGE_FRAME) | PAGE_PRESENT | PAGE_WRITABLE;
	}

	// store the canonical page in malloc header at the start of the allocation
	*((uintptr_t*)(start_shadow+offset)) = canon;

#ifdef __GC_WATERMARK
        if(invalidated_pages >= __GC_WATERMARK){
        invalidated_pages = 0;
                if(cur_span != NULL){
                        cur_span->last_sync = false;
                        cur_span = NULL;
                }
                gc_run();
        }
#endif

	// return the shadow page with the original in-page offset and canon padding
	return (uintptr_t*) (start_shadow + offset + sizeof(void*));
}

void* malloc(size_t size)
{
	if(process)
	{
		// call the original malloc with padded size
		void* canon = __libc_malloc(size + sizeof(void*));

		if(UNLIKELY(canon == NULL)) return NULL;
		
		// get the actual size of the allocated object (incl. alignment)
		const size_t usable_sz = malloc_usable_size(canon);

		// determine the offset of the object into its (first) page
		const size_t page_offset = (uintptr_t)canon & (PAGE_SIZE - 1);

		// determine how many pages the allocation spans
		const size_t num_pages = (usable_sz + page_offset - 1) / (PAGE_SIZE) + 1;

  		// create shadow
		uintptr_t* shadow_result = NULL;
		if(num_pages == 1){
			shadow_result = create_shadow_one((uintptr_t)canon, page_offset);
		}
		else{
			shadow_result = create_shadows((uintptr_t)canon, num_pages, page_offset);
		}
#ifdef __TRACK_SHADOW_SIZE
		nallocs++;
		if(nallocs % OUTPUT_FREQ == 0){
			output_shadow_size(false);
		}
#endif
		return (void*)shadow_result;
	}

	return __libc_malloc(size);
}

void* calloc(size_t nmemb, size_t size)
{
	if(process)
	{
		size_t numadj = 0, sizeadj = 0;
		// minimal adjustment
		if(nmemb==1)
			sizeadj = sizeof(void*);
		else if(size <= sizeof(void*))
			numadj = (sizeof(void*) + sizeof(void*)-1) / size;
		else{
			// consider: 10x500 bytes vs 500x10 bytes
			if((nmemb+1)*size < nmemb*(size+sizeof(void*)))
				numadj = 1;
			else
				sizeadj = sizeof(void*);
		}

		// padding may be more than 8 bytes, but thats ok
		void* canon = __libc_calloc(nmemb+numadj, size+sizeadj);
		if(UNLIKELY(canon == NULL)) return NULL;

		// get the actual size of the allocated object (incl. alignment)
		const size_t usable_sz = malloc_usable_size(canon);

		// determine the offset of the object into its (first) page
		const size_t page_offset = (uintptr_t)canon & (PAGE_SIZE - 1);

		// determine how many pages the allocation spans
		const size_t num_pages = (usable_sz + page_offset - 1) / (PAGE_SIZE) + 1;

		// create shadow
		uintptr_t* shadow_result = NULL;
		if(num_pages == 1){
			shadow_result = create_shadow_one((uintptr_t)canon, page_offset);
		}
		else{
			shadow_result = create_shadows((uintptr_t)canon, num_pages, page_offset);
		}
#ifdef __TRACK_SHADOW_SIZE
		nallocs++;
		if(nallocs % OUTPUT_FREQ == 0){
			output_shadow_size(false);
		}
#endif
		return (void*)shadow_result;
	}
	return __libc_calloc(nmemb, size);
}

void* realloc(void *ptr, size_t size)
{
	if(process)
	{
		// if ptr == NULL, call is equivalent to malloc(size)
		if(UNLIKELY(ptr==NULL)){
			return malloc(size);
		}

		// if size == zero, and ptr is not NULL, call equivalent to free(ptr);
		if(UNLIKELY(size == 0)){
			free(ptr);
			return NULL;
		}
#ifdef __SANITY_CHECK
		if((uintptr_t)ptr < SHADOW_BASE || (uintptr_t)ptr >= SHADOW_END){
			//fprintf(fp, "fatal: ptr out of range: %p\n", ptr);
			return __libc_realloc(ptr, size);
		}
#endif
		/* ptr mustve been obtained from malloc or calloc, so should be in shadow bounds anyway */

		// get the canonical address
		void* canon = (void*)(*(uintptr_t*)(ptr - sizeof(void*)));

		// get the size, offset, and number of pages of the old object
		const size_t pre_usable_sz = malloc_usable_size(canon);
		const size_t pre_page_offset = (uintptr_t)canon & (PAGE_SIZE - 1);
		const size_t pre_num_pages = (pre_usable_sz + pre_page_offset - 1) / (PAGE_SIZE) + 1;

		void* recanon = __libc_realloc(canon, size + sizeof(void*));
		if(UNLIKELY(recanon == NULL)) return NULL;

		// get the size, offset, and number of pages of the new object
		const size_t post_usable_sz = malloc_usable_size(recanon);
		const size_t post_page_offset = (uintptr_t)recanon & (PAGE_SIZE - 1);
		const size_t post_num_pages = (post_usable_sz + post_page_offset - 1) / (PAGE_SIZE) + 1;

		// NOTE: we cannot guarantee that we can extend the shadows in-place
		// since this depends on the state of the shadows
		// instead, we return a new shadow mapping

		// if realloc in place: check for identical or shrinking num pages

		if(canon == recanon){
		    if(pre_num_pages > post_num_pages){
		        // apply shrink
		        size_t num_remove = pre_num_pages - post_num_pages;
		        size_t startp = pre_num_pages - num_remove;
                	uintptr_t start_shadow = (uintptr_t)ptr + (startp * PAGE_SIZE);

                	// disable the shadows that cover the shrinkage
			if(num_remove == 1)
				disable_shadow_one(start_shadow & PAGE_MASK);
			else
                		disable_shadows(start_shadow & PAGE_MASK, num_remove);
		        return ptr;
		    }
		    else if(pre_num_pages == post_num_pages){
		        // identical pages in-place, do nothing
		        return ptr;
		    }
		}

		// disable the old shadow pages
        uintptr_t first_shadow = (uintptr_t)ptr & PAGE_MASK;
        if(pre_num_pages == 1){
                disable_shadow_one(first_shadow);
        }
        else{
                disable_shadows(first_shadow, pre_num_pages);
        }

		// else: reallocation is extended / moved (canon is free). free old shadows & create new
    	uintptr_t* shadow_result = NULL;
		if(post_num_pages == 1){
			shadow_result = create_shadow_one((uintptr_t)recanon, post_page_offset);
		}
		else{
			shadow_result = create_shadows((uintptr_t)recanon, post_num_pages, post_page_offset);
		}

#ifdef __TRACK_SHADOW_SIZE
		nallocs++;
		if(nallocs % OUTPUT_FREQ == 0){
			output_shadow_size(false);
		}
#endif
		return (void*)shadow_result;
	}
	return __libc_realloc(ptr, size);
}

void free(void* ptr)
{
	if(process)
	{
		// printf("[DangZero]: Free Shadow @ %p (cr3=%p)\n", ptr, g_cr3);

#ifdef __SANITY_CHECK
		if((uintptr_t)ptr < SHADOW_BASE || (uintptr_t)ptr >= SHADOW_END){
			//printf("[!!] request free non-shadow %p\n", ptr);
			__libc_free(ptr);
			return;
		}
#else
		if(UNLIKELY(ptr==NULL)){
			return;
		}
#endif
		
		void* canon = (void*)(*(uintptr_t*)(ptr - sizeof(void*)));

		// find out how many shadow pages were created for object
		const size_t usable_sz = malloc_usable_size(canon);
		const size_t page_offset = (uintptr_t)canon & (PAGE_SIZE - 1);
		const size_t num_pages = (usable_sz + page_offset - 1) / (PAGE_SIZE) + 1;

		// disable the shadow pages
		uintptr_t first_shadow = (uintptr_t)ptr & PAGE_MASK;
		if(num_pages == 1){
			disable_shadow_one(first_shadow);
		}
		else{
			disable_shadows(first_shadow, num_pages);
		}
#ifdef __GC
		// zero out
		memset(canon, 0, usable_sz);
#endif
		// free the original canonical object
		__libc_free(canon);

		return;
	}

	__libc_free(ptr);
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	if(process)
	{
		*memptr = malloc(size);
		if(*memptr != NULL) return 0;
		return 12; // ENOMEM
	}
	return __posix_memalign(memptr, alignment, size);
}

void* memalign(size_t alignment, size_t size)
{
	if(process)
	{
		return malloc(size);
	}
	return __libc_memalign(alignment, size);
}

void __attribute__((destructor)) exit_unload()
{
	if(process)
	{
#ifdef __GC
		// run GC once at the end
 		// gc_run();
#endif
		// printf("[DangZero]: Destructor exit\n");
		//fprintf(stderr, "[dangzero] destructor entry\n");
		//fflush(stderr);

#ifdef __TRACK_MEM_USAGE
#ifdef __NGINX_MODE
		struct rusage u;
		if(getrusage(RUSAGE_SELF, &u) == 0){
			printf("[mem-usage] ru_maxrss %lu\n", u.ru_maxrss);
		}
		printf("[mem-usage] max_pt_count %lu\n", max_pt_count);
		printf("[mem-usage] curr_pt_count %lu\n", curr_pt_count);
		fflush(stdout);
#else
		fprintf(stderr, "[setup-report] max_pt_count: %lu\n", max_pt_count);
		fprintf(stderr, "[setup-report] curr_pt_count: %lu\n", curr_pt_count);
//		fprintf(stderr, "[setup-report] maxrss_seen: %ld\n", maxrss_seen);
		fprintf(stderr, "[setup-report] end rusage-counters\n");
		fflush(stderr);
#endif
#endif

#ifdef __GC
		uint64_t end_addr = highest_shadow;
#else
		uint64_t end_addr = free_span.start;
#endif
		unsigned short pml4_index = PML4_SHADOW_START;
		unsigned short pdpt_index = 0, pde_index = 0;
		unsigned short end_pml4 = PML4_INDEX(end_addr);
		unsigned short end_pdpt = PDPT_INDEX(end_addr);
		unsigned short end_pde = PDE_INDEX(end_addr);
		uintptr_t *pdpt, *pde, *pte;
#if defined(__GC) && defined(__GC_PT_COMPRESS)
		bool cpt = false;
#endif

		// main loop: exhaust all entries
		while(pml4_index < end_pml4){
			pdpt = get_table_page(g_cr3, pml4_index);
			if(pdpt == NULL) { pml4_index++; continue; }
			pdpt_index = 0;
			while(pdpt_index <= MAX_PAGE_INDEX){
				pde = get_table_page(pdpt, pdpt_index);
				if(pde == NULL) { pdpt_index++; continue; }
				pde_index = 0;
				while(pde_index <= MAX_PAGE_INDEX){
#if defined(__GC) && defined(__GC_PT_COMPRESS)
					pte = get_table_page_L2cpt(pde, pde_index, &cpt);	
#else
					pte = get_table_page(pde, pde_index);
#endif
					if(pte == NULL) { pde_index++; continue; }
#if defined(__GC) && defined(__GC_PT_COMPRESS)
					// if compressed and page aligned
					if(cpt && (((uintptr_t)pte & 0xfff)==0))
#endif
					free_pages((unsigned long)pte, 0);
					pde_index++;
				}
				free_pages((unsigned long)pde, 0);
				pdpt_index++;
			}
			free_pages((unsigned long)pdpt, 0);
			pml4_index++;
		}

		// last pml4: pml4_index == end_pml4
		pdpt = get_table_page(g_cr3, pml4_index);
		if(pdpt != NULL) {
			pdpt_index = 0;
			while(pdpt_index <= end_pdpt){ // only till end
				pde = get_table_page(pdpt, pdpt_index);
				if(pde == NULL) { pdpt_index++; continue; }
				pde_index = 0;
				while(pde_index <= MAX_PAGE_INDEX){ // slight over approx
#if defined(__GC) && defined(__GC_PT_COMPRESS)
					pte = get_table_page_L2cpt(pde, pde_index, &cpt);
#else
					pte = get_table_page(pde, pde_index);
#endif
					if(pte == NULL) { pde_index++; continue; }
#if defined(__GC) && defined(__GC_PT_COMPRESS)
                                        // if compressed and page aligned
                                        if(cpt && (((uintptr_t)pte & 0xfff)==0))
#endif
					free_pages((unsigned long)pte, 0);
					pde_index++;
				}
				free_pages((unsigned long)pde, 0);
				pdpt_index++;
			}
			free_pages((unsigned long)pdpt, 0);
		}

#ifdef __GC
		// return the memory of freelist structures
		/*if(g_freelist != NULL){
			for(int i = 0; i < NUM_BUCKETS; i++){
				if(g_freelist[i].items.lh_first != NULL)
				{					
					freelist_reset(&g_freelist[i]);
				}
			}
			__libc_free(g_freelist);
		}*/

		if(opt_freelist != NULL && opt_freelist->items.lh_first != NULL){
			freelist_reset(opt_freelist);
			__libc_free(opt_freelist);
		}
#ifdef __GC_PT_COMPRESS
		// return the memory of compression freelist
		cpt_destruct();
#endif
#endif
#ifdef __TRACK_SHADOW_SIZE
		process=0;
		if(shw_fp != NULL) fclose(shw_fp);
		process=1;
#endif
		// printf("[DangZero]: Destructor done\n");
		//fprintf(stderr, "[dangzero] destructor exit\n");
		//fflush(stderr);
	}
}

void apply_fork_map(uintptr_t* p_cr3, struct map_pa_va* addr_map, size_t num_addrs)
{
	// we need to create the shadow tables again in the current process
	// and additionally need new physical backing for each PTE

#ifdef __GC
	uintptr_t end_addr = highest_shadow;
#else
	uintptr_t end_addr = free_span.start; // until the next free spot
#endif

	uintptr_t cur_addr = SHADOW_BASE;

	unsigned short pml4_index=PML4_SHADOW_START, pdpt_index, pde_index, pte_index;
	unsigned short max_pml4=PML4_INDEX(end_addr);
	uintptr_t *pdpt, *pde, *pte;
	uintptr_t *c_pdpt, *c_pde, *c_pte;
	size_t i = 0;
	size_t store_i;
	phys_addr_t p_pa;
	phys_addr_t last_pa = 0;
	phys_addr_t cow_back = 0;
	volatile int8_t tmp; // volatile for -O2

	while(pml4_index <= max_pml4){
		// get and copy pdpt
		pdpt = get_table_page(p_cr3, pml4_index);
		if(pdpt == NULL) { pml4_index++; cur_addr+=PML4_ADDR_OFFSET; continue; }
		c_pdpt = create_page_table(g_cr3, pml4_index);

		pdpt_index = 0;
		while(pdpt_index < 512){
			// get and copy pde
			pde = get_table_page(pdpt, pdpt_index);
			if(pde == NULL) { pdpt_index++; cur_addr+=PDPT_ADDR_OFFSET; continue; }
			c_pde = create_page_table(c_pdpt, pdpt_index);

			pde_index = 0;
			while(pde_index < 512){
				// get and copy pte
				pte = get_table_page(pde, pde_index);
				if(pte == NULL) { pde_index++; cur_addr+=PDE_ADDR_OFFSET; continue; }
				c_pte = create_page_table(c_pde, pde_index);

				pte_index = 0;
				while(pte_index < 512){
					// pte+pte_index points to phys page
					if(*(pte+pte_index) & PAGE_PRESENT){
						// phys page is present
						p_pa = *(pte+pte_index) & PAGE_FRAME;
						uint64_t flags = *(pte+pte_index) & ~(PAGE_FRAME);

						// obj not shared on prev pa
						if(p_pa != last_pa){

							// although PA may not be contiguous, VAs are, and shadows are often in sync with VAs
							store_i = i;
							int skip_2nd_loop = 0;
							if(i > 0)
								i += 1;

							for(; i < num_addrs; i++){
								if(addr_map[i].pa == p_pa){
									// in the child, access the VA to cause CoW backing
									tmp = *((int8_t*)addr_map[i].va);
									*((int8_t*)addr_map[i].va) = tmp;

									// look up the physical addr of the new backing
									cow_back = get_phys_addr_user(addr_map[i].va);

									// store PA in case next shadow shares it
									last_pa = p_pa;

									// found after prev
									skip_2nd_loop = 1;
									break;
								}
							}

							if(!skip_2nd_loop){
								// continue search from 0 to previously found index
								for(i = 0; i < store_i; i++){
									if(addr_map[i].pa == p_pa){
										tmp = *((int8_t*)addr_map[i].va);
										*((int8_t*)addr_map[i].va) = tmp;
										cow_back = get_phys_addr_user(addr_map[i].va);
										last_pa = p_pa;
										break;
									}
								}
							}
						}

						// update child shadow pte to the new physical backing
						if(cow_back != 0){
							// make the child shadow point there
							// *(c_pte+pte_index) = (cow_back & PAGE_FRAME) | PAGE_PRESENT | PAGE_WRITABLE;
							*(c_pte+pte_index) = (cow_back & PAGE_FRAME) | flags;

							// flush TLB not needed here in fresh process shadow table
							// fprintf(stderr, "fork (%p) VA=%p PA=%p > COW=%p\n", cur_addr, (void*)addr_map[i].va, (void*)p_pa, (void*)(cow_back & PAGE_FRAME));
							//printf("Fork: VA=%p PA=%p > COW=%p\n", (void*)addr_map[i].va, (void*)p_pa, (void*)(cow_back & PAGE_FRAME));
						}
					}

					cur_addr += PAGE_SIZE;
					if(cur_addr >= end_addr){
						// fprintf(stderr, "reached the end of shadows: %p\n", (void*)cur_addr);
#ifdef __GC
						// unset last_sync on all spans
						// force resync if fragmented
						// otherwise realign below is enough
						
						struct vp_span *span;
						/*if(opt_freelist != NULL && opt_freelist->items.lh_first != NULL){
							LIST_FOREACH(span, &(opt_freelist->items), freelist) {
								span->last_sync = false;
							}
						}*/

						struct vp_freelist *new_list = __libc_malloc(sizeof(struct vp_freelist)); 
        					memset(new_list, 0, sizeof(struct vp_freelist));
						if(opt_freelist != NULL){
							LIST_FOREACH(span, &(opt_freelist->items), freelist){
								freelist_free(new_list, (void*)span->start, span_num_pages(span));
							}
						}
						opt_freelist = new_list;
						cur_span = NULL;
						
						// re-alloc freelist with kmalloc
						// since CoW is not triggered on freelist
#ifdef __GC_PT_COMPRESS
						cpt_nuke();
#endif
#endif
						// realign free_span
						last_pdpt = c_pdpt;
						last_pde = c_pde;
						last_pte = c_pte;
						last_pml4_index = pml4_index;
						last_pdpt_index = pdpt_index;
						last_pde_index = pde_index;
						last_pte_index = pte_index;
						return;
					}
					pte_index++;
				}
				pde_index++;
			}
			pdpt_index++;
		}
	}
}

#ifdef __ENABLE_FORK_SUPPORT
pid_t fork(void)
{
	if(process)
	{
		//printf("[wrap]: fork caught\n");
		//fprintf(stderr, "enter fork\n");
		//fflush(stderr);

		// create sync for this fork (libc malloc - no instrument)
		fork_sync = mmap(NULL, sizeof(struct _fork_sync), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
		pthread_mutex_init(&fork_sync->mutex, &fork_mutex_attr);
		pthread_cond_init(&fork_sync->cond, &fork_cond_attr);
		fork_sync->copy_done = 0;

		//fflush(stderr);

		pid_t pid = __libc_fork();
		if(pid == 0){
			// child: save parent cr3
			uintptr_t* parent_cr3 = g_cr3;

			// call into kernel module
			size_t num_addrs;
			struct map_pa_va* addr_map;
			addr_map = dangzero_create_fork_map(parent_cr3, &num_addrs);
			if(addr_map == NULL){
				printf("fatal: could not create fork map in kmod!\n");
				return -1;
			}
			//printf("Obtained addr map of size %lu\n", num_addrs);
			//fprintf(stderr, "fork addr map size: %lu\n", num_addrs);

			// update global cr3 for child
			phys_addr_t ccr3;
			asm("movq %%cr3, %0" : "=r" (ccr3));
			g_cr3 = phys_to_virt(ccr3);

			//printf("[wrap] child CR3=%p, parent CR3=%p\n", g_cr3, parent_cr3);

			// copy shadow tables
			apply_fork_map(parent_cr3, addr_map, num_addrs);

			// free the kmod allocated mapping
			kfree(addr_map);

			// wake the parent
			pthread_mutex_lock(&fork_sync->mutex);
			fork_sync->copy_done = 1;
			pthread_cond_signal(&fork_sync->cond);
			//printf("[set to 1, signal raised]\n");
			pthread_mutex_unlock(&fork_sync->mutex);

			// clear fork_sync
			munmap(fork_sync, sizeof(struct _fork_sync));
			//fprintf(stderr, "fork done\n");
		}
		else{
			// parent: wait for child to finish copy
			pthread_mutex_lock(&fork_sync->mutex);
			while(!(fork_sync->copy_done)){
				//printf("[enter wait loop]\n"); // cannot print with cow here
				pthread_cond_wait(&fork_sync->cond, &fork_sync->mutex);
				//printf("[exit wait]\n");
			}
			pthread_mutex_unlock(&fork_sync->mutex);

			// clear fork_sync
			munmap(fork_sync, sizeof(struct _fork_sync));
		}

		return pid;
	}
	return __libc_fork();
}
#endif

#ifdef __CVE_MODE
void handler(int sig, siginfo_t* si, void* vcontext)
{
	uintptr_t addr = (uintptr_t)si->si_addr;
	if(addr >= SHADOW_BASE){
		fprintf(stderr, "Segfault at: %p\n", si->si_addr);
		// look up pte and check if invalidated
		uintptr_t *pdpt, *pde, *pte;
		unsigned short pml4_index, pdpt_index, pde_index, pte_index;

		pml4_index = PML4_INDEX(addr);
		pdpt = get_table_page(g_cr3, pml4_index); //pdpt=cr3+pml4_index
		if(UNLIKELY(pdpt == NULL)) _exit(0);

		pdpt_index = PDPT_INDEX(addr);
		pde = get_table_page(pdpt, pdpt_index); //pde=pdpt+pdpt_index
		if(UNLIKELY(pde == NULL)) _exit(0);

		pde_index = PDE_INDEX(addr);
		pte = get_table_page(pde, pde_index); //pte=pde+pde_index
		if(UNLIKELY(pte == NULL)) _exit(0);

		pte_index = PTE_INDEX(addr);

		if(*(pte+pte_index) & PTE_INVALIDATED){
			fprintf(stderr, "PTE was invalidated\n");
		}
		else{
			fprintf(stderr, "PTE still active...\n");
		}
	}
	else{
		fprintf(stderr, "Unknown segfault at %p\n", si->si_addr);
	}
	fflush(stderr);
	_exit(0);	
}
#endif

int8_t is_target(char *program, int argc, char** argv)
{
#ifdef __SPEC_MODE
	if(strstr(program, "run_base")){
#elif defined(__NGINX_MODE)
	if(strstr(program, "nginx") || strstr(program, "lighttpd")){
#elif defined(__JULIET_MODE)
	if(strstr(program, "CWE")){
#elif defined(__CVE_MODE)
	if(strstr(program, "consume")){
#else
	if(strstr(program, "hello") || strstr(program, "/trusted/") || strstr(program, "dz_")){
#endif

		//fukp = fopen("/home/u16/Documents/gclog.txt", "a");

		//fprintf(stderr, "set target: %s\n", program);
		/*char filename[256];
		unsigned long t = time(NULL);
		sprintf(filename, "%sout_%lu.txt", LOG_PATH, t);
		fp = fopen(filename, "w");
		if(!fp) return 0;*/

		//printf("[DangZero]: Target set: %s\n", program);
/*		int a;
		for(a = 0; a < argc; a++){
			fprintf(stderr, "argv %d: %s\n", a, argv[a]);
		}*/

#ifdef __CVE_MODE
		// segfault handler 
		struct sigaction action;
		memset(&action, 0, sizeof(struct sigaction));
		action.sa_flags = SA_SIGINFO;
		action.sa_sigaction = handler;
		sigaction(SIGSEGV, &action, NULL);
#endif

		//  global process cr3
		phys_addr_t pcr3;
		asm("movq %%cr3, %0" : "=r" (pcr3));
		g_cr3 = phys_to_virt(pcr3);

#ifdef __GC		
        opt_freelist = __libc_malloc(sizeof(struct vp_freelist)); 
        memset(opt_freelist, 0, sizeof(struct vp_freelist));
		struct vp_span *span = WM_ALLOC(sizeof(struct vp_span));
		span->start = SHADOW_BASE;
		span->end = SHADOW_END;
		span->last_sync = true; // set up below
		cur_span = span;
		LIST_INSERT_HEAD(&opt_freelist->items, span, freelist);
#endif

// if-not-GC?
		// set free span
		free_span.start = SHADOW_BASE;
		free_span.end = SHADOW_END;

		// set up page walk ptrs
		last_pdpt = step_shadow_table(g_cr3, PML4_SHADOW_START);
		last_pde = step_shadow_table(last_pdpt, 0);
		last_pte = step_shadow_table(last_pde, 0);

		__posix_memalign = (proto_posix_memalign) dlsym(RTLD_NEXT, "posix_memalign");

#ifdef __ENABLE_FORK_SUPPORT
		// look up kernel module function
		dangzero_create_fork_map = (proto_dangzero_create_fork_map) kallsyms_lookup_name("dangzero_create_fork_map");
		if(!dangzero_create_fork_map){
			printf("[fatal!!] DangZero Kmod lookup fork failed.\n");
			fflush(stdout);
      		fprintf(stderr, "[fatal!!] DangZero Kmod lookup fork failed.\n");
			fflush(stderr);
			return 0;
		}

		// set up attributes for fork sync
		pthread_mutexattr_init(&fork_mutex_attr);
		pthread_condattr_init(&fork_cond_attr);
		pthread_mutexattr_setpshared(&fork_mutex_attr, PTHREAD_PROCESS_SHARED);
		pthread_condattr_setpshared(&fork_cond_attr, PTHREAD_PROCESS_SHARED);
#endif

#ifdef __GC
		dangzero_find_vma_bounds = (proto_dangzero_find_vma_bounds) kallsyms_lookup_name("dangzero_find_vma_bounds");
		dangzero_mark_heap = (proto_dangzero_mark_heap) kallsyms_lookup_name("dangzero_mark_heap");
		if(!dangzero_find_vma_bounds || !dangzero_mark_heap){
				fprintf(stderr, "cannot find gc heap dangmod\n");
				return 0;
		}
#endif

		//fprintf(stderr, "set target done\n");
		return 1;
	}
	return 0;
}

typedef int (*main_t)(int, char, char);
typedef int (*libc_start_main_t)(main_t main, int argc, char** ubp_av,
			void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void* stack_end);

int __libc_start_main(main_t main, int argc, char** ubp_av,
			void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void* stack_end)
{
	libc_start_main_t og_libc_start_main = (libc_start_main_t)dlsym(RTLD_NEXT, "__libc_start_main");
	process = is_target(ubp_av[0], argc, ubp_av);
	og_libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);

}
