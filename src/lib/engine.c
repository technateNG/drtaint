#include <stdint.h>
#include "engine.h"

#define TAINTED_MEMORY_LEN 8192u

static size_t tainted_memory[TAINTED_MEMORY_LEN];
static uint64_t tainted_registers;

inline size_t is_memory_tainted(size_t addr)
{
	size_t pos = addr % TAINTED_MEMORY_LEN;
	return tainted_memory[pos];
}

inline void taint_memory(size_t addr)
{
	size_t pos = addr % TAINTED_MEMORY_LEN;
	tainted_memory[pos] = addr;
}

inline void untaint_memory(size_t addr)
{
	size_t pos = addr % TAINTED_MEMORY_LEN;
	tainted_memory[pos] = 0;
}

inline uint_fast8_t is_register_tainted(uint_fast8_t reg)
{
	return tainted_registers & 1 << reg;
}

inline void taint_register(uint_fast8_t reg)
{
	tainted_registers |= 1 << reg;
}

inline void untaint_register(uint_fast8_t reg)
{
	tainted_registers &= ~(1 << reg);
}

inline taint_res_t taint_rr_check(uint_fast8_t src, uint_fast8_t dst)
{
	taint_res_t flag = TAINT_NONE;
	if (is_register_tainted(src))
	{
		taint_register(dst);
		flag = TAINT_SPREAD;
	}
	else if (is_register_tainted(dst))
	{
		untaint_register(dst);
		flag = TAINT_SHRINK;
	}
	return flag;
}

inline taint_res_t taint_rm_check(uint_fast8_t src, size_t dst)
{
	taint_res_t flag = TAINT_NONE;
	if (is_register_tainted(src))
	{
		taint_memory(dst);
		flag = TAINT_SPREAD;
	}
	else if (is_memory_tainted(dst))
	{
		untaint_memory(dst);
		flag = TAINT_SHRINK;
	}
	return flag;
}

inline taint_res_t taint_mm_check(size_t src, size_t dst)
{
	taint_res_t flag = TAINT_NONE;
	if (is_memory_tainted(src))
	{
		taint_memory(dst);
		flag = TAINT_SPREAD;
	}
	else if (is_memory_tainted(dst))
	{
		untaint_memory(dst);
		flag = TAINT_SHRINK;
	}
	return flag;
}

inline taint_res_t taint_mr_check(size_t src, uint_fast8_t dst)
{
	taint_res_t flag = TAINT_NONE;
	if (is_memory_tainted(src))
	{
		taint_register(dst);
		flag = TAINT_SPREAD;
	}
	else if (is_register_tainted(dst))
	{
		untaint_register(dst);
		flag = TAINT_SHRINK;
	}
	return flag;
}