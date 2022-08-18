#include "imports.h"
#include "functions.h"

auto driver_entry() -> const NTSTATUS
{
    dbg( "at driver entry!\n" );

    auto win32k = utils::get_kernel_module( "win32k.sys" );
    if (!win32k) {
        dbg( "win32k not found!" );
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    //NtUserGetPointerProprietaryId
    //48 83 EC 28 48 8B 05 B5 8A
    globals::hook_address = win32k + 0x664E8;
    dbg( "NtUserGetPointerProprietaryId: %llX", globals::hook_address );

    globals::hook_pointer = *reinterpret_cast< uintptr_t* >( globals::hook_address );
    *reinterpret_cast< uintptr_t* >( globals::hook_address ) = reinterpret_cast< uintptr_t >( &hooked_function );

    dbg( "success!" );

    return STATUS_SUCCESS;
}