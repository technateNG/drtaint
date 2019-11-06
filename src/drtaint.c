#include <stddef.h>
#include <dr_api.h>
#include <drmgr.h>
#include <drreg.h>
#include <drutil.h>
#include <stdlib.h>
#include "engine.h"

typedef struct stack_ops
{
	app_pc pc;
	size_t start;
	size_t end;
} stack_ops_t;

stack_ops_t s_ops;

module_data_t* main_module;
app_pc init_instr_pc;

void rr_11_cc(reg_id_t src, reg_id_t dst, app_pc instr_pc)
{
	module_data_t* module = dr_lookup_module(instr_pc);
	taint_res_t flag = taint_rr_check(src, dst);
	if (flag == TAINT_SPREAD)
	{
		dr_printf("%p [SPREAD] %s => %s %s+%x\n",
			instr_pc,
			get_register_name(src),
			get_register_name(dst),
			module->names.file_name,
			instr_pc - module->start);
	}
	else if (flag == TAINT_SHRINK)
	{
		dr_printf("%p [SHRINK] %s =X %s %s+%x\n",
			instr_pc,
			get_register_name(src),
			get_register_name(dst),
			module->names.file_name,
			instr_pc - module->start);
	}
	dr_free_module_data(module);
}

void rm_11_cc(reg_id_t src, app_pc dst, app_pc instr_pc)
{
	module_data_t* module = dr_lookup_module(instr_pc);
	taint_res_t flag = taint_rm_check(src, dst);
	if (flag == TAINT_SPREAD)
	{
		dr_printf(
			"%p [SPREAD] %s => %p %s+%x\n",
			instr_pc,
			get_register_name(src),
			dst,
			module->names.file_name,
			instr_pc - module->start
		);
	}
	else if (flag == TAINT_SHRINK)
	{
		dr_printf(
			"%p [SHRINK] %s =X %p %s+%x\n",
			instr_pc,
			get_register_name(src),
			dst,
			module->names.file_name,
			instr_pc - module->start
		);
	}
	dr_free_module_data(module);
}

void mm_11_cc(app_pc src, app_pc dst, app_pc instr_pc)
{
	module_data_t* module = dr_lookup_module(instr_pc);
	taint_res_t flag = taint_mm_check(src, dst);
	if (flag == TAINT_SPREAD)
	{
		dr_printf(
			"%p [SPREAD] %p => %p %s+%x\n", 
			instr_pc, 
			src, 
			dst,
			module->names.file_name,
			instr_pc - module->start);
	}
	else if (flag == TAINT_SHRINK)
	{
		dr_printf(
			"%p [SHRINK] %p =X %p %s+%x\n", 
			instr_pc, 
			src, 
			dst, 
			module->names.file_name,
			instr_pc - module->start
		);
	}
	dr_free_module_data(module);
}

void mr_11_cc(app_pc src, reg_id_t dst, app_pc instr_pc)
{
	module_data_t* module = dr_lookup_module(instr_pc);
	taint_res_t flag = taint_mr_check(src, dst);
	if (flag == TAINT_SPREAD)
	{
		dr_printf(
			"%p [SPREAD] %p => %s %s+%x\n", 
			instr_pc, 
			src, 
			get_register_name(dst), 
			module->names.file_name,
			instr_pc - module->start
		);
	}
	else if (flag == TAINT_SHRINK)
	{
		dr_printf(
			"%p [SHRINK] %p =X %s %s+%x\n", 
			instr_pc, 
			src, 
			get_register_name(dst),
			module->names.file_name,
			instr_pc - module->start
		);
	}
	dr_free_module_data(module);
}

void im_11_cc(size_t imm, app_pc dst_pc, app_pc instr_pc)
{
	if (is_memory_tainted(dst_pc))
	{
		module_data_t* module = dr_lookup_module(instr_pc);
		dr_printf(
			"%p [SHRINK] %lu =X %p %s+%x\n", 
			instr_pc, 
			imm, 
			dst_pc, 
			module->names.file_name, 
			instr_pc - module->start
		);
		untaint_memory(dst_pc);
		dr_free_module_data(module);
	}
}

void ir_11_cc(size_t imm, reg_id_t dst_reg, app_pc instr_pc)
{
	if (is_register_tainted(dst_reg))
	{
		module_data_t* module = dr_lookup_module(instr_pc);
		dr_printf(
			"%p [SHRINK] %lu =X %s %s+%x\n",
			instr_pc,
			imm,
			get_register_name(dst_reg),
			module->names.file_name,
			instr_pc - module->start
		);
		untaint_register(dst_reg);
		dr_free_module_data(module);
	}
}

void init_cc(reg_id_t dst)
{
	taint_register(dst);
	dr_printf(
		"%p [INIT] <> => %s %s+%x\n",
		init_instr_pc + (uint64) main_module->start,
		get_register_name(dst),
		main_module->names.file_name,
		init_instr_pc
	);
}

void s_cc(void)
{
	dr_mcontext_t mcontext = { sizeof(dr_mcontext_t), DR_MC_CONTROL };
	dr_get_mcontext(dr_get_current_drcontext(), &mcontext);
	reg_t start = mcontext.xsp + s_ops.start;
	reg_t end = mcontext.xsp + s_ops.end;
	dr_printf("Stack: %p\n", mcontext.xsp);
	for (size_t i = start; i <= end; ++i)
	{
		taint_memory((app_pc) i);
	}
	dr_printf(
		"%p [INIT] %p <=> %p %s+%x\n",
		s_ops.pc + (uint64) main_module->start,
		start,
		end,
		main_module->names.file_name,
		s_ops.pc
	);
}

static inline void calculate_address_or_instrument(
	void* drcontext,
	instrlist_t* bb,
	instr_t* instr,
	opnd_t base,
	opnd_t dst
)
{
	dr_mcontext_t mcontext = { sizeof(dr_mcontext_t), DR_MC_CONTROL | DR_MC_INTEGER };
	dr_get_mcontext(drcontext, &mcontext);
	app_pc base_pc = opnd_compute_address(base, &mcontext);
	if (base_pc)
	{
		instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t) base_pc, dst, bb, instr, NULL, NULL);
	}
	else
	{
		reg_id_t a3;
		DR_ASSERT(drreg_reserve_register(drcontext, bb, instr, NULL, &a3) == DRREG_SUCCESS);
		drutil_insert_get_mem_addr(drcontext, bb, instr, base, opnd_get_reg(dst), a3);
		DR_ASSERT(drreg_unreserve_register(drcontext, bb, instr, a3) == DRREG_SUCCESS);
	}
}

#define INSTRUMENT_GET_INSTR_PC \
instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t) instr_pc, o_ia, bb, instr, NULL, NULL)

#define INSTRUMENT_LOAD_INT(val, dst) \
instrlist_meta_preinsert(bb, instr, XINST_CREATE_load_int(drcontext, dst, OPND_CREATE_INT32(opnd_get_reg(val))))

#define RESERVE_REGISTER(reg) drreg_reserve_register(drcontext, bb, instr, NULL, &reg)
#define UNRESERVE_REGISTER(reg) drreg_unreserve_register(drcontext, bb, instr, reg)

static dr_emit_flags_t event_app_instruction(
	void* drcontext,
	void* tag,
	instrlist_t* bb,
	instr_t* instr,
	bool for_trace,
	bool translating,
	void* user_data)
{
	if (instr_is_app(instr))
	{
		app_pc instr_pc = instr_get_app_pc(instr);
		size_t n_src = instr_num_srcs(instr);
		size_t n_dst = instr_num_dsts(instr);
		if (n_src <= 2 && n_dst == 1)
		{
			opnd_t src = instr_get_src(instr, 0);
			opnd_t dst = instr_get_dst(instr, 0);
			if (instr_pc == init_instr_pc)
			{
				reg_id_t a1;
				DR_ASSERT(
					RESERVE_REGISTER(a1) == DRREG_SUCCESS
				);
				opnd_t o_a1 = opnd_create_reg(a1);
				INSTRUMENT_LOAD_INT(dst, o_a1);
				dr_insert_clean_call(drcontext, bb, instr, init_cc, false, 1, o_a1);

				DR_ASSERT(
					UNRESERVE_REGISTER(a1) == DRREG_SUCCESS
				);
			}
			else if (s_ops.pc == instr_pc)
			{
				dr_insert_clean_call(drcontext, bb, instr, s_cc, false, 0);
			}
			else
			{
				if (opnd_is_reg(src))
				{
					reg_id_t a1, a2, ia;
					DR_ASSERT(
						RESERVE_REGISTER(a1) == DRREG_SUCCESS
						&& RESERVE_REGISTER(a2) == DRREG_SUCCESS
						&& RESERVE_REGISTER(ia) == DRREG_SUCCESS
					);
					opnd_t o_a1 = opnd_create_reg(a1);
					opnd_t o_a2 = opnd_create_reg(a2);
					opnd_t o_ia = opnd_create_reg(ia);

					if (opnd_is_reg(dst))
					{
						INSTRUMENT_LOAD_INT(src, o_a1);
						INSTRUMENT_LOAD_INT(dst, o_a2);
						INSTRUMENT_GET_INSTR_PC;
						dr_insert_clean_call(drcontext, bb, instr, rr_11_cc, false, 3, o_a1, o_a2, o_ia);
					}
					else if (opnd_is_memory_reference(dst))
					{
						INSTRUMENT_LOAD_INT(src, o_a1);
						calculate_address_or_instrument(drcontext, bb, instr, dst, o_a2);
						INSTRUMENT_GET_INSTR_PC;
						dr_insert_clean_call(drcontext, bb, instr, rm_11_cc, false, 3, o_a1, o_a2, o_ia);
					}

					DR_ASSERT(
						UNRESERVE_REGISTER(a1) == DRREG_SUCCESS
						&& UNRESERVE_REGISTER(a2) == DRREG_SUCCESS
						&& UNRESERVE_REGISTER(ia) == DRREG_SUCCESS
					);
				}
				else if (opnd_is_memory_reference(src))
				{
					reg_id_t a1, a2, ia;
					DR_ASSERT(
						RESERVE_REGISTER(a1) == DRREG_SUCCESS
						&& RESERVE_REGISTER(a2) == DRREG_SUCCESS
						&& RESERVE_REGISTER(ia) == DRREG_SUCCESS
					);
					opnd_t o_a1 = opnd_create_reg(a1);
					opnd_t o_a2 = opnd_create_reg(a2);
					opnd_t o_ia = opnd_create_reg(ia);

					if (opnd_is_reg(dst))
					{
						calculate_address_or_instrument(drcontext, bb, instr, src, o_a1);
						INSTRUMENT_LOAD_INT(dst, o_a2);
						INSTRUMENT_GET_INSTR_PC;
						dr_insert_clean_call(drcontext, bb, instr, mr_11_cc, false, 3, o_a1, o_a2, o_ia);
					}
					else if (opnd_is_memory_reference(dst))
					{
						calculate_address_or_instrument(drcontext, bb, instr, src, o_a1);
						calculate_address_or_instrument(drcontext, bb, instr, dst, o_a2);
						INSTRUMENT_GET_INSTR_PC;
						dr_insert_clean_call(drcontext, bb, instr, mm_11_cc, false, 3, o_a1, o_a2, o_ia);
					}

					DR_ASSERT(
						UNRESERVE_REGISTER(a1) == DRREG_SUCCESS
						&& UNRESERVE_REGISTER(a2) == DRREG_SUCCESS
						&& UNRESERVE_REGISTER(ia) == DRREG_SUCCESS
					);
				}
				else if (opnd_is_immed(src))
				{
					reg_id_t a1, a2, ia;
					DR_ASSERT(
						RESERVE_REGISTER(a1) == DRREG_SUCCESS
						&& RESERVE_REGISTER(a2) == DRREG_SUCCESS
						&& RESERVE_REGISTER(ia) == DRREG_SUCCESS
					);
					opnd_t o_a1 = opnd_create_reg(a1);
					opnd_t o_a2 = opnd_create_reg(a2);
					opnd_t o_ia = opnd_create_reg(ia);
					instrlist_meta_preinsert(bb, instr, 
						XINST_CREATE_load_int(drcontext, o_a1, OPND_CREATE_INT64(opnd_get_immed_int(src))));
					INSTRUMENT_GET_INSTR_PC;
					if (opnd_is_reg(dst))
					{
						INSTRUMENT_LOAD_INT(dst, o_a2);
						dr_insert_clean_call(drcontext, bb, instr, ir_11_cc, false, 3, o_a1, o_a2, o_ia);
					}
					else if (opnd_is_memory_reference(dst))
					{
						calculate_address_or_instrument(drcontext, bb, instr, dst, o_a2);
						dr_insert_clean_call(drcontext, bb, instr, im_11_cc, false, 3, o_a1, o_a2, o_ia);
					}
					DR_ASSERT(
						UNRESERVE_REGISTER(a1) == DRREG_SUCCESS
						&& UNRESERVE_REGISTER(a2) == DRREG_SUCCESS
						&& UNRESERVE_REGISTER(ia) == DRREG_SUCCESS
					);
				}
			}
		}
	}
	return DR_EMIT_DEFAULT;
}

static void event_exit(void)
{
	dr_free_module_data(main_module);
	drmgr_unregister_bb_insertion_event(event_app_instruction);
	drreg_exit();
	drmgr_exit();
}

static void parse_ops(int argc, const char* argv[])
{
	switch (argv[1][0])
	{
	case 'I':
	{
		size_t offset = strtoll(argv[2], NULL, 16);
		init_instr_pc = main_module->start + offset;
		break;
	}
	case 'S':
	{
		s_ops.pc = main_module->start + strtoll(argv[2], NULL, 16);
		s_ops.start = strtoll(argv[3], NULL, 10);
		s_ops.end = strtoll(argv[4], NULL, 10);
		break;
	}
	case 'A':
	{
		size_t start = strtoll(argv[2], NULL, 16);
		size_t end = strtoll(argv[3], NULL, 16);
		for (size_t i = start; i <= end; ++i)
		{
			insert_in_taint_memory((app_pc)i);
		}
	}
	default:
	{
		DR_ASSERT(false);
	}
	}
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char* argv[])
{
	dr_set_client_name("drtaint", "???");
	drreg_options_t ops = {
			.struct_size = sizeof(drreg_options_t),
			.num_spill_slots = 4,
			.conservative = false
	};
	main_module = dr_get_main_module();
	dr_printf("%s: %p - %p\n", main_module->names.file_name, main_module->start, main_module->end);
	parse_ops(argc, argv);
	if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS)
	{
		DR_ASSERT(false);
	}
	drutil_init();
	dr_register_exit_event(event_exit);
	if (
		!drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL)
		)
	{
		DR_ASSERT(false);
	}
}
