#include <stdint.h>

typedef enum taint_res
{
	TAINT_NONE = 0,
	TAINT_SPREAD = 1,
	TAINT_SHRINK = 2
} taint_res_t;

inline size_t is_memory_tainted(size_t pc);

inline void taint_memory(size_t pc);

inline void untaint_memory(size_t pc);

inline uint_fast8_t is_register_tainted(uint_fast8_t reg);

inline void taint_register(uint_fast8_t reg);

inline void untaint_register(uint_fast8_t reg);

inline taint_res_t taint_rr_check(uint_fast8_t src, uint_fast8_t dst);

inline taint_res_t taint_mr_check(size_t src, uint_fast8_t dst);

inline taint_res_t taint_mm_check(size_t src, size_t dst);

inline taint_res_t taint_rm_check(uint_fast8_t src, size_t dst);