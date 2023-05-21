#pragma once

auto readvm( _requests* in ) -> bool
{
	PEPROCESS source_process = NULL;
	if ( in->src_pid == 0 ) return STATUS_UNSUCCESSFUL;

	NTSTATUS status = PsLookupProcessByProcessId( ( HANDLE )in->src_pid, &source_process);
	if (status != STATUS_SUCCESS) return false;

	size_t memsize = 0;

	if ( !NT_SUCCESS( utils::readprocessmemory( source_process, ( void* )in->src_addr, ( void* )in->dst_addr, in->size, &memsize) ) )
		return false;

	ObDereferenceObject( source_process );

	return true;
}

auto move_mouse( _requests* in ) -> bool
{
//hackerman https://www.unknowncheats.me/forum/members/1595354.html
	MOUSE_INPUT_DATA input;

	input.LastX = in->x;
	input.LastY = in->y;
	input.ButtonFlags = in->button_flags;

	KIRQL irql;
	KeRaiseIrql( DISPATCH_LEVEL, &irql );

	ULONG ret;
	utils::mouse.service_callback( utils::mouse.mouse_device, &input, ( PMOUSE_INPUT_DATA )&input + 1, &ret );

	KeLowerIrql(irql);

	return true;
}

auto requesthandler( _requests* pstruct ) -> bool
{
	if ( !utils::mouse.service_callback || !utils::mouse.mouse_device )
		utils::setup_mouclasscallback( &utils::mouse );

	switch ( pstruct->request_key ) {

	case DRIVER_GETPOOL:
		return pstruct->allocation = utils::find_guarded_region();

	case DRIVER_READVM:
		return readvm( pstruct );

	case DRIVER_MOUSE:
		return move_mouse( pstruct );
	}

	return true;
}

auto hooked_function( uintptr_t rcx ) -> void
{
	_requests* in = ( _requests* )rcx;
	requesthandler( in );
}
