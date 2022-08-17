class _driver
{
private:
	typedef INT64(*Nt_UserGetPointerProprietaryId)(uintptr_t);
	Nt_UserGetPointerProprietaryId NtUserGetPointerProprietaryId = nullptr;

#define DRIVER_READVM				0x80000001
#define DRIVER_GETPOOL				0x80000002

	int _processid;

	struct _requests {
		uint32_t    src_pid;
		uint64_t    src_addr;
		uint64_t    dst_addr;
		size_t        size;
		int request_key;
		std::uintptr_t allocation;
	};

public:
	auto initdriver( int processid ) -> void
	{
		NtUserGetPointerProprietaryId = ( Nt_UserGetPointerProprietaryId )GetProcAddress( LoadLibraryA( "win32u.dll" ), "NtUserGetPointerProprietaryId" );
		if ( NtUserGetPointerProprietaryId != 0 )
		{
			printf( "NtUserGetPointerProprietaryId: %p\n", NtUserGetPointerProprietaryId );
			_processid = processid;
		}
	}

	auto readvm( uint32_t src_pid, uint64_t src_addr, uint64_t dst_addr, size_t size ) -> void
	{
		_requests out = { src_pid, src_addr, dst_addr, size, DRIVER_READVM };
		NtUserGetPointerProprietaryId( reinterpret_cast< uintptr_t >( &out ) );
	}

	auto guarded_region() -> uintptr_t
	{
		_requests out = { 0 };
		out.request_key = DRIVER_GETPOOL;
		NtUserGetPointerProprietaryId( reinterpret_cast< uintptr_t >( &out ) );
		return out.allocation;
	}

	template <typename T>
	T readguarded( uint64_t guardedregion, uintptr_t src, size_t size = sizeof(T) )
	{
		T buffer;
		readvm( _processid, src, ( uintptr_t )&buffer, size );
		uintptr_t val = guardedregion + ( *( uintptr_t* )&buffer & 0xFFFFFF );
		return *(T*)&val;
	}

	template <typename T>
	T read( uintptr_t src, size_t size = sizeof(T) )
	{
		T buffer;
		readvm( _processid, src, ( uintptr_t )&buffer, size );
		return buffer;
	}
};

_driver driver;
