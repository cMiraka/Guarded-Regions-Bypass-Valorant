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
}
