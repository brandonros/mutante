#include <ntifs.h>
#include "log.h"
#include "utils.h"
#include "shared.h"
#include "smbios.h"

#define VENDOR "BESSTAR TECH LIMITED\0"
#define MANUFACTURER "BESSTAR TECH LIMITED\0"
#define PRODUCT_NAME "B450I GAMING PLUS MAX WIFI (MS-7A40)\0"
#define SERIAL_NUMBER "Default string\0"

/**
 * \brief Get's the string from SMBIOS table
 * \param header Table header
 * \param string String itself
 * \return Pointer to the null terminated string
 */
char* Smbios::GetString(SMBIOS_HEADER* header, SMBIOS_STRING string)
{
  const auto* start = reinterpret_cast<const char*>(header) + header->Length;

  if (!string || *start == 0)
    return nullptr;

  while (--string)
  {
    start += strlen(start) + 1;
  }

  return const_cast<char*>(start);
}

/**
 * \brief Modify information in the table of given header
 * \param header Table header (only 0-3 implemented)
 * \return 
 */
NTSTATUS Smbios::ProcessTable(SMBIOS_HEADER* header)
{
  if (!header->Length)
    return STATUS_UNSUCCESSFUL;

  if (header->Type == 0)
  {
    auto* type0 = reinterpret_cast<SMBIOS_TYPE0*>(header);

    auto* vendor = GetString(header, type0->Vendor);
    memcpy(vendor, VENDOR, strlen(VENDOR) + 1);
  }

  if (header->Type == 1)
  {
    auto* type1 = reinterpret_cast<SMBIOS_TYPE1*>(header);

    auto* manufacturer = GetString(header, type1->Manufacturer);
    memcpy(manufacturer, MANUFACTURER, strlen(MANUFACTURER) + 1);

    auto* productName = GetString(header, type1->ProductName);
    memcpy(productName, PRODUCT_NAME, strlen(PRODUCT_NAME) + 1);

    auto* serialNumber = GetString(header, type1->SerialNumber);
    memcpy(serialNumber, SERIAL_NUMBER, strlen(SERIAL_NUMBER) + 1);
  }

  if (header->Type == 2)
  {
    auto* type2 = reinterpret_cast<SMBIOS_TYPE2*>(header);

    auto* manufacturer = GetString(header, type2->Manufacturer);
    memcpy(manufacturer, MANUFACTURER, strlen(MANUFACTURER) + 1);

    auto* productName = GetString(header, type2->ProductName);
    memcpy(productName, PRODUCT_NAME, strlen(PRODUCT_NAME) + 1);

    auto* serialNumber = GetString(header, type2->SerialNumber);
    memcpy(serialNumber, SERIAL_NUMBER, strlen(SERIAL_NUMBER) + 1);
  }

  if (header->Type == 3)
  {
    auto* type3 = reinterpret_cast<SMBIOS_TYPE3*>(header);

    auto* manufacturer = GetString(header, type3->Manufacturer);
    memcpy(manufacturer, MANUFACTURER, strlen(MANUFACTURER) + 1);

    auto* serialNumber = GetString(header, type3->SerialNumber);
    memcpy(serialNumber, SERIAL_NUMBER, strlen(SERIAL_NUMBER) + 1);
  }
  
  return STATUS_SUCCESS;
}

/**
 * \brief Loop through SMBIOS tables with provided first table header
 * \param mapped Header of the first table
 * \param size Size of all tables including strings
 * \return 
 */
NTSTATUS Smbios::LoopTables(void* mapped, ULONG size)
{
  auto* endAddress = static_cast<char*>(mapped) + size;
  while (true)
  {
    auto* header = static_cast<SMBIOS_HEADER*>(mapped);
    if (header->Type == 127 && header->Length == 4)
      break;
    
    ProcessTable(header);
    auto* end = static_cast<char*>(mapped) + header->Length;
    while (0 != (*end | *(end + 1))) end++;
    end += 2;
    if (end >= endAddress)
      break;  

    mapped = end;
  }
  
  return STATUS_SUCCESS;
}

/**
 * \brief Find SMBIOS physical address, map it and then loop through
 * table 0-3 and modify possible identifiable information
 * \return Status of the change (will return STATUS_SUCCESS if mapping was successful)
 */
NTSTATUS Smbios::ChangeSmbiosSerials()
{
  auto* base = Utils::GetModuleBase("ntoskrnl.exe");
  if (!base)
  {
    Log::Print("Failed to find ntoskrnl.sys base!\n");
    return STATUS_UNSUCCESSFUL;
  }

  auto* physicalAddress = static_cast<PPHYSICAL_ADDRESS>(Utils::FindPatternImage(base, "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15", "xxx????xxxx?xx")); // WmipFindSMBiosStructure -> WmipSMBiosTablePhysicalAddress
  if (!physicalAddress)
  {
    Log::Print("Failed to find SMBIOS physical address!\n");
    return STATUS_UNSUCCESSFUL;
  }

  physicalAddress = reinterpret_cast<PPHYSICAL_ADDRESS>(reinterpret_cast<char*>(physicalAddress) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(physicalAddress) + 3));
  if (!physicalAddress)
  {
    Log::Print("Physical address is null!\n");
    return STATUS_UNSUCCESSFUL;
  }

  auto* sizeScan = Utils::FindPatternImage(base, "\x8B\x1D\x00\x00\x00\x00\x48\x8B\xD0\x44\x8B\xC3\x48\x8B\xCD\xE8\x00\x00\x00\x00\x8B\xD3\x48\x8B", "xx????xxxxxxxxxx????xxxx");  // WmipFindSMBiosStructure -> WmipSMBiosTableLength
  if (!sizeScan)
  {
    Log::Print("Failed to find SMBIOS size!\n");
    return STATUS_UNSUCCESSFUL;
  }

  const auto size = *reinterpret_cast<ULONG*>(static_cast<char*>(sizeScan) + 6 + *reinterpret_cast<int*>(static_cast<char*>(sizeScan) + 2));
  if (!size)
  {
    Log::Print("SMBIOS size is null!\n");
    return STATUS_UNSUCCESSFUL;
  }

  auto* mapped = MmMapIoSpace(*physicalAddress, size, MmNonCached);
  if (!mapped)
  {
    Log::Print("Failed to map SMBIOS structures!\n");
    return STATUS_UNSUCCESSFUL;
  }
  
  LoopTables(mapped, size);
  
  MmUnmapIoSpace(mapped, size);
  
  return STATUS_SUCCESS;
}
