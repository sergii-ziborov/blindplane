#include <stdio.h>
#include <IOKit/IOKitLib.h>
int try_open(const char *cls) {
    CFMutableDictionaryRef m = IOServiceMatching(cls);
    if (!m) { printf("%-16s no matching dict\n", cls); return 1; }
    io_iterator_t it;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault, m, &it);
    if (kr != KERN_SUCCESS) { printf("%-16s GetMatchingServices kr=0x%x\n", cls, kr); return 1; }
    io_service_t svc; int found = 0;
    while ((svc = IOIteratorNext(it))) {
        found++;
        io_name_t nm; IORegistryEntryGetName(svc, nm);
        io_connect_t conn = 0;
        // try several user client types
        for (int t = 0; t < 3; t++) {
            kr = IOServiceOpen(svc, mach_task_self(), t, &conn);
            printf("%-16s service='%s' IOServiceOpen(type=%d) kr=0x%08x (%s)\n",
                   cls, nm, t, kr, kr == KERN_SUCCESS ? "OPENED" :
                   (kr == kIOReturnNotPermitted ? "NOT PERMITTED" :
                   (kr == kIOReturnNotPrivileged ? "NOT PRIVILEGED" : "denied/other")));
            if (kr == KERN_SUCCESS) { IOServiceClose(conn); break; }
        }
        IOObjectRelease(svc);
    }
    IOObjectRelease(it);
    if (!found) printf("%-16s no such service in IORegistry\n", cls);
    return 0;
}
int main(void) {
    const char *classes[] = {"AppleH11ANEInterface","H11ANEIn","AppleH16ANEInterface","AppleANELoadBalancer", NULL};
    for (int i = 0; classes[i]; i++) try_open(classes[i]);
    return 0;
}
