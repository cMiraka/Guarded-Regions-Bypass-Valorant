#pragma once

auto readvm( _requests* in ) -> bool
{
	PEPROCESS source_process = NULL;
	if ( in->src_pid == 0 ) return STATUS_UNSUCCESSFUL;

	NTSTATUS status = PsLookupProcessByProcessId( ( HANDLE )in->src_pid, &source_process);
	if (status != STATUS_SUCCESS) return false;

	size_t memsize = 0;
	void* buffer = ExAllocatePoolWithTag( NonPagedPool, in->size, 'DieH' );
	if ( !buffer )
		return false;

	if ( !NT_SUCCESS( utils::readprocessmemory( source_process, ( void* )in->src_addr, buffer, in->size, &memsize) ) )
		return false;

	if ( !NT_SUCCESS( utils::writeprocessmemory( PsGetCurrentProcess(), ( void* )in->dst_addr, buffer, in->size, &memsize ) ) )
		return false;

	ObDereferenceObject( source_process );

	ExFreePoolWithTag( buffer, 'DieH' );

	return true;
}

auto requesthandler( _requests* pstruct ) -> bool
{
	switch ( pstruct->request_key ) {

	case DRIVER_GETPOOL:
		return pstruct->allocation = utils::find_guarded_region();
		break;

	case DRIVER_READVM:
		return readvm( pstruct );
		break;
	}

	return true;
}

auto hooked_function( uintptr_t rcx ) -> void
{
	_requests* in = ( _requests* )rcx;
	requesthandler( in );
}