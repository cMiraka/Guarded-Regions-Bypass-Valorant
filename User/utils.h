namespace utils
{
	auto getprocessid( std::wstring processname ) -> uintptr_t
	{
		auto snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
		PROCESSENTRY32W entry;
		entry.dwSize = sizeof( entry );
		if ( !Process32First( snapshot, &entry ) ) {
			return 0;
		}
		while ( Process32Next( snapshot, &entry ) ) {
			if ( std::wstring (entry.szExeFile ) == processname) {
				return entry.th32ProcessID;
			}
		}
		return 0;
	}

	auto getuworld( uintptr_t pointer ) -> uintptr_t
	{
		uintptr_t uworld_addr = driver.readv< uintptr_t >( pointer + offsets::uworldptr );

		unsigned long long uworld_offset;

		if ( uworld_addr > 0x10000000000 )
		{
			uworld_offset = uworld_addr - 0x10000000000;
		}
		else {
			uworld_offset = uworld_addr - 0x8000000000;
		}

		return pointer + uworld_offset;
	}

//bluefire1337
	inline static bool isguarded( uintptr_t pointer ) noexcept
	{
		static constexpr uintptr_t filter = 0xFFFFFFF000000000;
		uintptr_t result = pointer & filter;
		return result == 0x8000000000 || result == 0x10000000000;
	}
}
