#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg-op.h"

#include <tlbsim.h>

///
/// TLB infrastracture
///

static uint64_t phys_load(tlbsim_client_t *self, uint64_t address) {
    return ldq_phys(current_cpu->as, address);
}

static bool phys_cmpxchg(tlbsim_client_t *self, uint64_t address, uint64_t old, uint64_t new) {
    MemoryRegion *mr;
    hwaddr l = sizeof(target_ulong), addr1;
    mr = address_space_translate(current_cpu->as, address,
        &addr1, &l, false, MEMTXATTRS_UNSPECIFIED);
    if (memory_region_is_ram(mr)) {
        target_ulong *pa =
            qemu_map_ram_ptr(mr->ram_block, addr1);
        target_ulong result = atomic_cmpxchg(pa, old, new);
        if (result != old) {
            return false;
        }
        return true;
    } else {
        /* ROM (AD bits are not preset) or in IO space */
        return false;
    }
}

static void invalidate_l0(tlbsim_client_t *self, int hartid, uint64_t vpn, int type) {
    CPUState *cpu;
    if (RISCV_CPU(current_cpu)->env.mhartid == hartid) {
        cpu = current_cpu;
    } else {
        CPU_FOREACH(cpu) {
            if (RISCV_CPU(cpu)->env.mhartid == hartid) break;
        }
    }
    int mmuidx = (type & 1 ? 0xf : 0) | (type & 2 ? 0xf0 : 0);
    if (vpn == 0) {
        tlb_flush_by_mmuidx(cpu, mmuidx);
    } else {
        tlb_flush_page_by_mmuidx(cpu, vpn << PGSHIFT, mmuidx);
    }
}

tlbsim_client_t tlbsim_client = {
    .phys_load = phys_load,
    .phys_cmpxchg = phys_cmpxchg,
    .invalidate_l0 = invalidate_l0,
};

int riscv_tlb_access(CPURISCVState* env, hwaddr *physical, int *prot,
        target_ulong addr, int access_type, int mmu_idx)
{
    int mode = mmu_idx & 3;

    if (mode == PRV_M && access_type != MMU_INST_FETCH) {
        if (get_field(env->mstatus, MSTATUS_MPRV)) {
            mode = get_field(env->mstatus, MSTATUS_MPP);
        }
    }

    if (mode == PRV_M || !riscv_feature(env, RISCV_FEATURE_MMU) ||
            !get_field(env->satp, SATP_MODE)) {
        *physical = addr;
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return TRANSLATE_SUCCESS;
    }

    int mxr = get_field(env->mstatus, MSTATUS_MXR);
    tlbsim_req_t req = {
        .satp = env->satp,
        .vpn = addr >> PGSHIFT,
        .asid = get_field(env->satp, SATP_ASID),
        .hartid = env->mhartid,
        .ifetch = access_type == MMU_INST_FETCH,
        .write = access_type == MMU_DATA_STORE,
        .supervisor = mode != 0,
        .mxr = mxr,
        .sum = access_type == MMU_INST_FETCH ? 0 : get_field(env->mstatus, MSTATUS_SUM),
    };

    tlbsim_resp_t resp = tlbsim_access(&req);
    if (!resp.perm) return TRANSLATE_FAIL;

    *physical = resp.ppn << PGSHIFT;
    *prot = 0;
    if ((resp.pte & PTE_R) || ((resp.pte & PTE_X) && mxr)) {
        *prot |= PAGE_READ;
    }
    if ((resp.pte & PTE_X)) {
        *prot |= PAGE_EXEC;
    }
    if ((resp.pte & PTE_W) && (resp.pte & PTE_D)) {
        *prot |= PAGE_WRITE;
    }
    return TRANSLATE_SUCCESS;
}

