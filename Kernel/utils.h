namespace utils
{
    uintptr_t context_cr3 = 0;

    auto get_system_information( const SYSTEM_INFORMATION_CLASS information_class ) -> const void *
    {
        unsigned long size = 32;
        char buffer[32];

        ZwQuerySystemInformation( information_class, buffer, size, &size );

        const auto info = ExAllocatePool( NonPagedPool, size );

        if ( !info )
        {
            return nullptr;
        }

        if ( ZwQuerySystemInformation( information_class, info, size, &size ) != STATUS_SUCCESS )
        {
            ExFreePool( info );
            return nullptr;
        }

        return info;
    }   

    auto get_kernel_module( const char *name ) -> const uintptr_t
    {
        const auto to_lower = []( char *string ) -> const char *{
            for ( char *pointer = string; *pointer != '\0'; ++pointer )
            {
                *pointer = ( char )( short )tolower( *pointer );
            }

            return string;
        };

        const auto info = ( PRTL_PROCESS_MODULES )get_system_information( system_module_information );

        if ( !info )
        {
            return 0;
        }

        for ( auto i = 0ull; i < info->number_of_modules; ++i )
        {
            const auto &module = info->modules[i];

            if ( strcmp( to_lower( ( char * )module.full_path_name + module.offset_to_file_name ), name ) == 0 )
            {
                const auto address = module.image_base;

                ExFreePool( info );

                return reinterpret_cast< uintptr_t > ( address );
            }
        }

        ExFreePool( info );

        return 0;
    }

    typedef struct ShadowRegionsDataStructure
    {
        uintptr_t OriginalPML4_t;
        uintptr_t ClonedPML4_t;
        uintptr_t GameCr3;
        uintptr_t ClonedCr3;
        uintptr_t FreeIndex;
    } ShadowRegionsDataStructure;

    // simplified decryption for non-HVCI mode; HVCI version varies a little, use the decryption routine from vgk.sys for it
    auto decrypt_cloned_cr3_simplified(uintptr_t cloned_cr3) -> uintptr_t
    {
        uintptr_t Last = cloned_cr3 & 0xFFFFFFFFF;
        uintptr_t FirstDigit = Last >> 32 & 0xF;
        uintptr_t LastDigit = Last & 0xF;

        FirstDigit -= 1;
        LastDigit -= 1;

        return FirstDigit << 32 | Last & 0x0FFFFFFF0 | LastDigit;
    }

    auto find_pml4_base() -> uintptr_t
    {
        auto vgk = utils::get_kernel_module("vgk.sys");
        if (!vgk) {
            dbg("vgk not found!");
            return 0;
        }

        auto ShadowRegionsData = *(ShadowRegionsDataStructure*)(vgk + 0x89488);
        if (!ShadowRegionsData.GameCr3) {
            dbg("ShadowRegionsData not found!");
            return 0;
        }

        // set read/write translation context to the decrypted cloned cr3
        context_cr3 = decrypt_cloned_cr3_simplified(ShadowRegionsData.ClonedCr3);

        return ShadowRegionsData.FreeIndex << 0x27;
    }

    //from https://www.unknowncheats.me/forum/anti-cheat-bypass/444289-read-process-physical-memory-attach.html
    DWORD getoffsets()
    {
        RTL_OSVERSIONINFOW ver = { 0 };
        RtlGetVersion( &ver );

        switch (ver.dwBuildNumber)
        {
        case WINDOWS_1803:
            return 0x0278;
            break;
        case WINDOWS_1809:
            return 0x0278;
            break;
        case WINDOWS_1903:
            return 0x0280;
            break;
        case WINDOWS_1909:
            return 0x0280;
            break;
        case WINDOWS_2004:
            return 0x0388;
            break;
        case WINDOWS_20H2:
            return 0x0388;
            break;
        case WINDOWS_21H1:
            return 0x0388;
            break;
        default:
            return 0x0388;
        }
    }

    auto readphysaddress( PVOID address, PVOID buffer, SIZE_T size, SIZE_T* read ) -> NTSTATUS
    {
        if (!address)
            return STATUS_UNSUCCESSFUL;

        MM_COPY_ADDRESS addr = { 0 };
        addr.PhysicalAddress.QuadPart = ( LONGLONG )address;
        return MmCopyMemory( buffer, addr, size, MM_COPY_MEMORY_PHYSICAL, read );
    }

    auto writephysaddress( PVOID address, PVOID buffer, SIZE_T size, SIZE_T* written ) -> NTSTATUS
    {
        if (!address)
            return STATUS_UNSUCCESSFUL;

        PHYSICAL_ADDRESS addr = { 0 };
        addr.QuadPart = (LONGLONG)address;

        auto mapped_mem = MmMapIoSpaceEx( addr, size, PAGE_READWRITE );

        if (!mapped_mem)
            return STATUS_UNSUCCESSFUL;

        memcpy( mapped_mem, buffer, size );

        *written = size;
        MmUnmapIoSpace( mapped_mem, size );
        return STATUS_SUCCESS;
    }

    auto translateaddress( uint64_t processdirbase, uint64_t address ) -> uint64_t
    {
        processdirbase &= ~0xf;

        uint64_t pageoffset = address & ~( ~0ul << PAGE_OFFSET_SIZE );
        uint64_t pte = ( ( address >> 12 ) & ( 0x1ffll ) );
        uint64_t pt = ( ( address >> 21 ) & ( 0x1ffll ) );
        uint64_t pd = ( ( address >> 30 ) & ( 0x1ffll ) );
        uint64_t pdp = ( ( address >> 39 ) & ( 0x1ffll ) );

        SIZE_T readsize = 0;
        uint64_t pdpe = 0;
        readphysaddress( ( void* )( processdirbase + 8 * pdp ), &pdpe, sizeof( pdpe ), &readsize );
        if (~pdpe & 1)
            return 0;

        uint64_t pde = 0;
        readphysaddress( ( void* )( ( pdpe & mask) + 8 * pd ), &pde, sizeof( pde ), &readsize );
        if (~pde & 1)
            return 0;

        if (pde & 0x80)
            return ( pde & ( ~0ull << 42 >> 12 ) ) + ( address & ~( ~0ull << 30 ) );

        uint64_t ptraddr = 0;
        readphysaddress( ( void* )( ( pde & mask ) + 8 * pt ), &ptraddr, sizeof( ptraddr ), &readsize );
        if (~ptraddr & 1)
            return 0;

        if (ptraddr & 0x80)
            return ( ptraddr & mask ) + ( address & ~( ~0ull << 21) );

        address = 0;
        readphysaddress( ( void* ) ( ( ptraddr & mask ) + 8 * pte ), &address, sizeof( address ), &readsize );
        address &= mask;

        if (!address)
            return 0;

        return address + pageoffset;
    }

    auto readprocessmemory( PEPROCESS process, PVOID address, PVOID buffer, SIZE_T size, SIZE_T* read ) -> NTSTATUS
    {
        auto process_dirbase = context_cr3;

        SIZE_T curoffset = 0;
        while (size)
        {
            auto addr = translateaddress( process_dirbase, ( ULONG64 )address + curoffset );
            if ( !addr) return STATUS_UNSUCCESSFUL;

            ULONG64 readsize = min( PAGE_SIZE - (addr & 0xFFF ), size);
            SIZE_T readreturn = 0;
            auto readstatus = readphysaddress( ( void* )addr, ( PVOID )( ( ULONG64 )buffer + curoffset), readsize, &readreturn );
            size -= readreturn;
            curoffset += readreturn;
            if ( readstatus != STATUS_SUCCESS ) break;
            if ( readreturn == 0 ) break;
        }

        *read = curoffset;
        return STATUS_SUCCESS;
    }

    auto writeprocessmemory( PEPROCESS process, PVOID address, PVOID buffer, SIZE_T size, SIZE_T* written ) -> NTSTATUS
    {
        auto process_dirbase = context_cr3;

        SIZE_T curoffset = 0;
        while (size)
        {
            auto addr = translateaddress( process_dirbase, ( ULONG64 )address + curoffset);
            if (!addr) return STATUS_UNSUCCESSFUL;

            ULONG64 writesize = min( PAGE_SIZE - ( addr & 0xFFF ), size);
            SIZE_T written = 0;
            auto writestatus = writephysaddress( (void*)addr, ( PVOID )( ( ULONG64 )buffer + curoffset), writesize, &written );
            size -= written;
            curoffset += written;
            if ( writestatus != STATUS_SUCCESS ) break;
            if ( written == 0 ) break;
        }

        *written = curoffset;
        return STATUS_SUCCESS;
    }

    //tt nbq#7049
    auto setup_mouclasscallback( PMOUSE_OBJECT mouse_obj ) -> NTSTATUS
    {
        UNICODE_STRING mouclass;
        RtlInitUnicodeString( &mouclass, L"\\Driver\\MouClass" );

        PDRIVER_OBJECT mouclass_obj = NULL;
        NTSTATUS status = ObReferenceObjectByName( &mouclass, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&mouclass_obj );

        UNICODE_STRING mouhid;
        RtlInitUnicodeString( &mouhid, L"\\Driver\\MouHID" );

        PDRIVER_OBJECT mouhid_obj = NULL;
        status = ObReferenceObjectByName( &mouhid, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&mouhid_obj );

        PDEVICE_OBJECT mouhid_deviceobj = mouhid_obj->DeviceObject;

        while ( mouhid_deviceobj && !mouse_obj->service_callback )
        {
            PDEVICE_OBJECT mouclass_deviceobj = mouclass_obj->DeviceObject;
            while ( mouclass_deviceobj && !mouse_obj->service_callback )
            {
                if ( !mouclass_deviceobj->NextDevice && !mouse_obj->mouse_device )
                {
                    mouse_obj->mouse_device = mouclass_deviceobj;
                }

                PULONG_PTR deviceobj_extension = ( PULONG_PTR )mouhid_deviceobj->DeviceExtension;
                ULONG_PTR deviceobj_ext_size = ( ( ULONG_PTR )mouhid_deviceobj->DeviceObjectExtension - ( ULONG_PTR )mouhid_deviceobj->DeviceExtension ) / 4;

                for ( ULONG_PTR i = 0; i < deviceobj_ext_size; i++ )
                {
                    if (deviceobj_extension[i] == ( ULONG_PTR )mouclass_deviceobj && deviceobj_extension[i + 1] > ( ULONG_PTR )mouclass_obj )
                    {
                        mouse_obj->service_callback = ( MouseClassServiceCallback )(deviceobj_extension[i + 1] );
                        break;
                    }
                }
                mouclass_deviceobj = mouclass_deviceobj->NextDevice;
            }
            mouhid_deviceobj = mouhid_deviceobj->AttachedDevice;
        }

        if ( !mouse_obj->mouse_device )
        {
            PDEVICE_OBJECT target_device_object = mouclass_obj->DeviceObject;
            while ( target_device_object )
            {
                if ( !target_device_object->NextDevice )
                {
                    mouse_obj->mouse_device = target_device_object;
                    break;
                }
                target_device_object = target_device_object->NextDevice;
            }
        }

        ObDereferenceObject( mouclass_obj );
        ObDereferenceObject( mouhid_obj );

        return status;
    }

    //MOUSE_OBJECT mouse;
}