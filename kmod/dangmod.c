#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/pid.h> // for ?
#include <linux/sched.h> // for current
#include <linux/fs.h> // for file name
#include <linux/dcache.h>
#include <linux/mm.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("fcg");
MODULE_DESCRIPTION("DangZero kmod");
MODULE_VERSION("0.1");

typedef int (*proto_mark_ptr)(uintptr_t ptr);
proto_mark_ptr mark_ptr;

// cat /proc/kallsyms | grep "test_func"

// page table indexing
#define _PAGE_MASK 0x000ffffffffff000UL
#define PAGE_MASK_INDEX 0x1FF // 511
#define MAX_PAGE_INDEX 511
#define PML4_INDEX(x)	((x >> 39) & PAGE_MASK_INDEX)
#define PDPT_INDEX(x)	((x >> 30) & PAGE_MASK_INDEX)
#define PDE_INDEX(x)	((x >> 21) & PAGE_MASK_INDEX)
#define PTE_INDEX(x)	((x >> 12) & PAGE_MASK_INDEX)

//typedef uint64_t phys_addr_t;
#define SHADOW_BASE 0xffff960000000000
#define SHADOW_END 0xffffc87fffffffff

// arch/x86/include/asm/pgtable_types.h
#define PAGE_PRESENT 1

// array option (waste space, faster than list)
struct map_pa_va {
	uintptr_t pa;
	uintptr_t va;
};

static inline bool is_potential_ptr(uintptr_t v)
{
   return SHADOW_BASE <= v && v <= SHADOW_END;
}

static uintptr_t* get_table_page(uintptr_t* table, unsigned short index)
{
	uintptr_t page = *(table+index);
	if(!(page & PAGE_PRESENT))
		return NULL;

	return (uintptr_t*)((page & _PAGE_MASK) + PAGE_OFFSET);
}

phys_addr_t get_phys_addr_user(uintptr_t addr, uintptr_t* cr3)
{
	uintptr_t* page = cr3;
	phys_addr_t phys_page;
	unsigned short index;

	// level 4
	index = PML4_INDEX(addr);
	page = get_table_page(page, index);
	if(page == NULL) return 0;

	// level 3
	index = PDPT_INDEX(addr);
	page = get_table_page(page, index);
	if(page == NULL) return 0;

	// level 2
	index = PDE_INDEX(addr);
	page = get_table_page(page, index);
	if(page == NULL) return 0;

	// phys page
	index = PTE_INDEX(addr);
	phys_page = *(page+index);
	if(!(phys_page & PAGE_PRESENT)) return 0;

	return phys_page;
}



int dangzero_find_vma_bounds(uintptr_t ptr, uintptr_t* start, uintptr_t* end)
{
	struct vm_area_struct *vma = 0;
	if(current->mm && current->mm->mmap){
		for(vma = current->mm->mmap; vma; vma = vma->vm_next){
			if(vma->vm_start <= ptr && ptr < vma->vm_end){
				*start = vma->vm_start;
				if(stack_guard_page_start(vma, *start))
					*start += PAGE_SIZE;
				*end = vma->vm_end;
				if(stack_guard_page_end(vma, *end))
					*end -= PAGE_SIZE;
				return 1;
			}
		}
	}
		return 0;
}

bool gc_skip_vma(struct vm_area_struct* vma)
{
/*	if(vma->vm_start <= vma->vm_mm->brk &&
           vma->vm_end >= vma->vm_mm->start_brk){
                return false;
        }
//	if(vma->vm_flags & VM_GROWSDOWN){
//		return false;
//	}
	return true;*/

	char *buf, *p;
	struct file *file = vma->vm_file;
	// vdso
	if(!vma->vm_mm){
		return true;
	}

	if(file){
		// read-only executable file
		if(!(vma->vm_flags & VM_WRITE) && (vma->vm_flags & VM_EXEC)){
			return true;
		}
		// lazy loaded file
		else if(!(vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC))){
			return true;
		}
/*
		buf = kmalloc(256, GFP_KERNEL);
		p = d_path(&file->f_path, buf, 256);
		if(strstr(p, ".so")){
			//printk("skip vma: %s\n", p);
			kfree(buf);
			return true;
		}
		kfree(buf);*/
	}

	return false;
}

bool fork_skip_vma(struct vm_area_struct* vma)
{
	/*
	// option test: [heap] only
	if(vma->vm_start <= vma->vm_mm->brk &&
	   vma->vm_end >= vma->vm_mm->start_brk){
		return false;
	}
	return true; // all that are not heap
	*/

	// vdso
	if(!vma->vm_mm){
		return true;
	}
	// stack
	else if(vma->vm_flags & VM_GROWSDOWN){
		return true;
	}
	// file maps
	else if(vma->vm_file){
		// read-only executable file
		if(!(vma->vm_flags & VM_WRITE) && (vma->vm_flags & VM_EXEC)){
			return true;
		}
		// lazy loaded file
		else if(!(vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC))){
			return true;
		}
	}

	return false;
}

void dangzero_mark_heap(void* func_mark_ptr)
{
	struct vm_area_struct *vma;
	uintptr_t *data;
	ssize_t i;
	unsigned long start, end;
	mark_ptr = (proto_mark_ptr)func_mark_ptr;

	if(current->mm && current->mm->mmap){
		for(vma = current->mm->mmap; vma; vma = vma->vm_next){
			if(!gc_skip_vma(vma)){

				// make sure we dont access guard pages (segfault)
				start = vma->vm_start;
				if(stack_guard_page_start(vma, start))
					start += PAGE_SIZE;
				end = vma->vm_end;
				if(stack_guard_page_end(vma, end))
					end -= PAGE_SIZE;

				data = (uintptr_t*) start;

				for(i = 0; i < (end-start)/sizeof(void*); i++){
					if (is_potential_ptr(data[i])){
		               	mark_ptr(data[i]);
					}
				}
			}
		}
	}
}


struct map_pa_va* dangzero_create_fork_map(uintptr_t* cr3, size_t* num_addrs_ret)
{
	struct vm_area_struct *vma = 0;
	uintptr_t vpage;
	size_t num_pages=0;
	size_t num_addrs=0;

	// init struct
	struct map_pa_va* addr_map = NULL;

	if(current->mm && current->mm->mmap){
		//printk("current user app: %s\n", current->comm);

		for(vma = current->mm->mmap; vma; vma = vma->vm_next){
			if(!fork_skip_vma(vma)){
				num_pages += (vma->vm_end - vma->vm_start) / PAGE_SIZE;
			}
		}

		// kmalloc max size is 4MB
		// sizeof(struct map_pa_va) == 16 bytes
		// max kmalloc can fit 250 000 structs (pages)
		// which is 1 GB of mapped memory

		addr_map = kmalloc(sizeof(struct map_pa_va) * num_pages, GFP_KERNEL);
		if(addr_map == NULL){
			return NULL;
		}

		for(vma = current->mm->mmap; vma; vma = vma->vm_next){
			if(!fork_skip_vma(vma)){
				//printk("%08lx-%08lx\n", vma->vm_start, vma->vm_end);
				for(vpage = vma->vm_start; vpage < vma->vm_end; vpage+=PAGE_SIZE){
					phys_addr_t pa = get_phys_addr_user(vpage, cr3);
					if(pa != 0){
						//printk("VA %p -> PA %p\n", (void*)vpage, (void*)(pa & PAGE_MASK));
						addr_map[num_addrs].va = vpage;
						addr_map[num_addrs].pa = pa & _PAGE_MASK;
						num_addrs++;
					}
				}
			}
		}
	}

	//printk("Result ptr=%p, size addrs=%lu\n", addr_map, num_addrs);

	*num_addrs_ret = num_addrs;
	return addr_map;
}



static int __init kmod_init(void) {
	printk(KERN_INFO "Init DangZero Kmod.\n");
	return 0;
}

static void __exit kmod_exit(void) {
	printk(KERN_INFO "Exit DangZero Kmod.\n");
}

module_init(kmod_init);
module_exit(kmod_exit);
