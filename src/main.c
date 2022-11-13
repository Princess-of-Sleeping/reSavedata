/*
 * PS Vita RE-Savedata
 * Copyright (C) 2022, Princess of Sleeping
 */

#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/io/stat.h>
#include <taihen.h>


#define HookImport(module_name, library_nid, func_nid, func_name) taiHookFunctionImportForKernel(KERNEL_PID, &func_name ## _ref, module_name, library_nid, func_nid, func_name ## _patch)
#define HookOffset(modid, seg_index, thumb, offset, func_name) taiHookFunctionOffsetForKernel(KERNEL_PID, &func_name ## _ref, modid, seg_index, offset, thumb, func_name ## _patch);


char rs_path[0x40];


tai_hook_ref_t sceAppMgrGetSavedataPath_ref;
int sceAppMgrGetSavedataPath_patch(const char *app0_base, const char *titleid, int flags, const char *sfo_category, char *savedata_path, SceSize savedata_path_len){

	int res;
	SceIoStat stat;

	res = TAI_CONTINUE(int, sceAppMgrGetSavedataPath_ref, app0_base, titleid, flags, sfo_category, savedata_path, savedata_path_len);
	if(res >= 0 && strcmp(sfo_category, "gd") == 0){
		snprintf(savedata_path, savedata_path_len, "%s/%s", rs_path, titleid);

		if(ksceIoGetstat(savedata_path, &stat) == 0x80010002){ // SCE_ERROR_ERRNO_ENOENT
			ksceIoMkdir(savedata_path, 0606);
		}
	}

	return res;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args){

	int res;
	SceIoStat stat;
	tai_module_info_t info;
	info.size = sizeof(info);

	if(taiGetModuleInfoForKernel(KERNEL_PID, "SceAppMgr", &info) < 0){
		return SCE_KERNEL_START_FAILED;
	}

	do {
		res = ksceIoGetstat("host0:/data", &stat);
		if(res >= 0){
			snprintf(rs_path, sizeof(rs_path), "%s/resavedata", "host0:/data");
			break;
		}

		res = ksceIoGetstat("ux0:/data", &stat);
		if(res >= 0){
			snprintf(rs_path, sizeof(rs_path), "%s/resavedata", "ux0:/data");
			break;
		}
	} while(0);

	if(res < 0){
		ksceDebugPrintf("Not found reSavedata base\n");
		return SCE_KERNEL_START_FAILED;
	}

	res = ksceIoMkdir(rs_path, 0606);
	if(res < 0 && res != 0x80010011){
		ksceDebugPrintf("sceIoMkdir 0x%X\n", res);
		return SCE_KERNEL_START_FAILED;
	}

	switch(info.module_nid){
	case 0xDBB29DB7: // 3.60
		HookOffset(info.modid, 0, 1, 0x17904, sceAppMgrGetSavedataPath);
		break;
	case 0x94CEFE4B: // 3.55
	case 0x1C9879D6: // 3.65
	case 0x54E2E984: // 3.67
	case 0xC3C538DE: // 3.68
	case 0x321E4852: // 3.69
	case 0x700DA0CD: // 3.70
	case 0xF7846B4E: // 3.71
	case 0xA8E80BA8: // 3.72
	case 0xB299D195: // 3.73
	default:
		return SCE_KERNEL_START_FAILED;
		break;
	}

	return SCE_KERNEL_START_SUCCESS;
}
