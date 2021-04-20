/*
 * PS Vita RE savedata
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/io/stat.h>
#include <psp2kern/fios2.h>
#include <taihen.h>

#define HookImport(module_name, library_nid, func_nid, func_name) taiHookFunctionImportForKernel(KERNEL_PID, &func_name ## _ref, module_name, library_nid, func_nid, func_name ## _patch)
#define HookOffset(modid, seg_index, thumb, offset, func_name) taiHookFunctionOffsetForKernel(KERNEL_PID, &func_name ## _ref, modid, seg_index, offset, thumb, func_name ## _patch);

typedef struct SceSelfAuthInfo { // size is 0x90
   SceUInt64 program_authority_id;
   uint8_t padding1[8];
   uint8_t capability[0x20];
   uint8_t attribute[0x20];
   uint8_t padding2[0x10];
   uint8_t klicensee[0x10];
   uint32_t unk_70;
   uint32_t unk_74;
   uint32_t unk_78;
   uint32_t unk_7C;
   uint32_t unk_80; // ex: 0x10
   uint32_t unk_84;
   uint32_t unk_88;
   uint32_t unk_8C;
} SceSelfAuthInfo;

#define RE_SAVEDATA_PATH "ux0:resavedata"

int write_file(const char *path, const void *data, size_t size){

	SceUID fd;

	fd = ksceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
	if(fd < 0){
		return fd;
	}

	ksceIoWrite(fd, data, size);
	ksceIoClose(fd);

	return 0;
}

const char sdslot_magic[] = {
	'S', 'D', 'S', 'L',
	0x0, 0x0, 0x0, 0x0,
	0x0, 0x1, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0
};

tai_hook_ref_t sceAppMgrInitSafemem_ref;
int sceAppMgrInitSafemem_patch(SceUID pid, int a2, const char *savedata0_sce_sys_path, char *a4, SceSize safemem_size){

	int res = 0;
	SceUID memid;
	void *mem_base = NULL;
	SceIoStat stat;
	char path[0x100], titleid[0x20], process_path_savedata0[0x20];
	SceSelfAuthInfo auth_info;

	memset(process_path_savedata0, 0, sizeof(process_path_savedata0));

	ksceSysrootGetSelfAuthInfo(pid, &auth_info);

	if((strncmp(titleid, "NPXS", 4) == 0) || (auth_info.program_authority_id == 0x2808000000000000)){
		goto tai_continue;
	}

	snprintf(path, sizeof(path), "%s/%s", savedata0_sce_sys_path, "safemem.dat");
	if(ksceIoGetstat(path, &stat) < 0){

		memid = ksceKernelAllocMemBlock("ReSdslot", SCE_KERNEL_MEMBLOCK_TYPE_RW_UNK0, safemem_size, NULL);

		ksceKernelGetMemBlockBase(memid, &mem_base);

		write_file(path, mem_base, safemem_size);

		ksceKernelFreeMemBlock(memid);
	}

	ksceFiosKernelOverlayResolveSync(pid, 1, "savedata0:", process_path_savedata0, sizeof(process_path_savedata0));

	if(strncmp(process_path_savedata0, "savedata0:", 10) == 0){
		goto tai_continue;
	}

	ksceKernelSysrootGetProcessTitleId(pid, titleid, sizeof(titleid));

	snprintf(path, sizeof(path), "%s/%s/", RE_SAVEDATA_PATH, titleid);

	res = ksceIoGetstat(path, &stat);
	if(res < 0){
		goto tai_continue;
	}

	// ksceIoMkdir(path, 0666);

	snprintf(path, sizeof(path), "%s/%s/sce_sys/", RE_SAVEDATA_PATH, titleid);

	res = ksceIoGetstat(path, &stat);
	if(res < 0)
		ksceIoMkdir(path, 0666);

	snprintf(path, sizeof(path), "%s/%s/sce_sys/%s", RE_SAVEDATA_PATH, titleid, "safemem.dat");
	if(ksceIoGetstat(path, &stat) < 0){

		memid = ksceKernelAllocMemBlock("ReSafemem", SCE_KERNEL_MEMBLOCK_TYPE_RW_UNK0, safemem_size, NULL);

		ksceKernelGetMemBlockBase(memid, &mem_base);

		write_file(path, mem_base, safemem_size);

		ksceKernelFreeMemBlock(memid);
	}

	snprintf(path, sizeof(path), "%s/%s/sce_sys/%s", RE_SAVEDATA_PATH, titleid, "sdslot.dat");
	if(ksceIoGetstat(path, &stat) < 0){

		memid = ksceKernelAllocMemBlock("ReSdslot", SCE_KERNEL_MEMBLOCK_TYPE_RW_UNK0, 0x50000, NULL);

		ksceKernelGetMemBlockBase(memid, &mem_base);

		memcpy(mem_base, sdslot_magic, 16);

		write_file(path, mem_base, 0x40400);

		ksceKernelFreeMemBlock(memid);
	}

tai_continue:
	return TAI_CONTINUE(int, sceAppMgrInitSafemem_ref, pid, a2, savedata0_sce_sys_path, a4, safemem_size);
}

tai_hook_ref_t ksceFiosKernelOverlayAddForProcess_ref;
int ksceFiosKernelOverlayAddForProcess_patch(SceUID pid, SceFiosOverlay *overlay, SceFiosOverlayID *outID){

	int res;
	SceFiosOverlay loc_overlay;

	if(strcmp(overlay->dst, "savedata0:") == 0){

		memcpy(&loc_overlay, overlay, sizeof(loc_overlay));

		char titleid[0x20];
		ksceKernelSysrootGetProcessTitleId(pid, titleid, sizeof(titleid));

		if(strcmp(titleid, "main") != 0){
			snprintf(loc_overlay.src, sizeof(loc_overlay.src), "%s/%s/", RE_SAVEDATA_PATH, titleid);

			SceIoStat stat;
			res = ksceIoGetstat(loc_overlay.src, &stat);
			if(res >= 0){
				overlay = &loc_overlay;
			}
		}
	}

	return TAI_CONTINUE(int, ksceFiosKernelOverlayAddForProcess_ref, pid, overlay, outID);
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args){

	tai_module_info_t info;
	info.size = sizeof(info);

	if(taiGetModuleInfoForKernel(KERNEL_PID, "SceAppMgr", &info) < 0)
		return SCE_KERNEL_START_FAILED;

	switch(info.module_nid){
	case 0x94CEFE4B: // 3.55
		HookOffset(info.modid, 0, 1, 0x2DF9C, sceAppMgrInitSafemem);
		break;
	case 0xDBB29DB7: // 3.60
		HookOffset(info.modid, 0, 1, 0x2E0C4, sceAppMgrInitSafemem);
		break;
	case 0x1C9879D6: // 3.65
		HookOffset(info.modid, 0, 1, 0x2E0AC, sceAppMgrInitSafemem);
		break;
	case 0x54E2E984: // 3.67
	case 0xC3C538DE: // 3.68
		HookOffset(info.modid, 0, 1, 0x2E0BC, sceAppMgrInitSafemem);
		break;
	case 0x321E4852: // 3.69
	case 0x700DA0CD: // 3.70
	case 0xF7846B4E: // 3.71
	case 0xA8E80BA8: // 3.72
	case 0xB299D195: // 3.73
		HookOffset(info.modid, 0, 1, 0x2E0E4, sceAppMgrInitSafemem);
		break;
	default:
		return SCE_KERNEL_START_FAILED;
		break;
	}

	HookImport("SceAppMgr", 0x54D6B9EB, 0x17E65A1C, ksceFiosKernelOverlayAddForProcess);

	return SCE_KERNEL_START_SUCCESS;
}
