#include <ntifs.h>
#include <windef.h>
#include <ntimage.h>
#include "shared.h"
#include "utils.h"

/**
 * \brief Get base address of kernel module
 * \param moduleName Name of the module (ex. storport.sys)
 * \return Address of the module or null pointer if failed
 */
PVOID Utils::GetModuleBase(const char* moduleName)
{
	PVOID address = nullptr;
	ULONG size = 0;

	auto status = ZwQuerySystemInformation(SystemModuleInformation, &size, 0, &size);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
		return nullptr;

	auto* moduleList = static_cast<PSYSTEM_MODULE_INFORMATION>(ExAllocatePoolWithTag(NonPagedPool, size, POOL_TAG));
	if (!moduleList)
		return nullptr;

	status = ZwQuerySystemInformation(SystemModuleInformation, moduleList, size, nullptr);
	if (!NT_SUCCESS(status))
		goto end;

	for (auto i = 0; i < moduleList->ulModuleCount; i++)
	{
		auto module = moduleList->Modules[i];
		if (strstr(module.ImageName, moduleName))
		{
			address = module.Base;
			break;
		}
	}

end:
	ExFreePool(moduleList);
	return address;
}
