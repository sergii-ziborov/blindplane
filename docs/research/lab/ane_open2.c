#include <stdio.h>
#include <IOKit/IOKitLib.h>
static const char* name_of(kern_return_t kr){
  switch(kr){
    case 0: return "SUCCESS";
    case 0xe00002bc: return "kIOReturnError";
    case 0xe00002c0: return "kIOReturnNoDevice";
    case 0xe00002c1: return "kIOReturnNotPrivileged";
    case 0xe00002c2: return "kIOReturnBadArgument";
    case 0xe00002c5: return "kIOReturnExclusiveAccess";
    case 0xe00002c7: return "kIOReturnUnsupported";
    case 0xe00002e2: return "kIOReturnNotPermitted";
    case 0xe00002eb: return "kIOReturnNotFound";
    default: return "other";
  }
}
int main(void){
  io_iterator_t it; io_service_t svc;
  IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("H11ANEIn"), &it);
  while((svc=IOIteratorNext(it))){
    io_name_t nm; IORegistryEntryGetName(svc,nm);
    printf("service '%s'\n", nm);
    for(int t=0;t<16;t++){
      io_connect_t c=0;
      kern_return_t kr=IOServiceOpen(svc, mach_task_self(), t, &c);
      printf("  type=%2d kr=0x%08x %s\n", t, kr, name_of(kr));
      if(kr==0) IOServiceClose(c);
    }
    IOObjectRelease(svc);
  }
  IOObjectRelease(it);
  return 0;
}
